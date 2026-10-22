'use strict';

const net = require('net');
const crypto = require('crypto');
const { createLogger } = require('./logger');
const {
  NoiseHandshake,
  NoiseSession,
  exportRawPublicKey,
} = require('./crypto/noise');

const DEFAULT_CONFIG = {
  listenAddr: '/ip4/0.0.0.0/tcp/4001',
  bootstrapPeers: [],
  gossipTopic: 'sorotask/keeper/assignments',
  heartbeatIntervalMs: 10000,
  maxPeers: 50,
  epochDurationMs: 60000,
  vrfSeed: process.env.KEEPER_VRF_SEED || crypto.randomBytes(32).toString('hex'),
  enableTcpMesh: true,
  allowedPeerIdentities: null, // null = allow any valid ed25519 identity, or Set/Array of hex keys
};

function parseMultiaddr(addr) {
  if (typeof addr === 'number') {
    return { host: '127.0.0.1', port: addr };
  }
  if (typeof addr !== 'string') {
    return { host: '127.0.0.1', port: 0 };
  }
  // Matches /ip4/127.0.0.1/tcp/4001 or 127.0.0.1:4001
  const ip4Match = addr.match(/\/ip4\/([^/]+)\/tcp\/(\d+)/);
  if (ip4Match) {
    return { host: ip4Match[1], port: parseInt(ip4Match[2], 10) };
  }
  const hostPortMatch = addr.match(/^([^:]+):(\d+)$/);
  if (hostPortMatch) {
    return { host: hostPortMatch[1], port: parseInt(hostPortMatch[2], 10) };
  }
  return { host: '0.0.0.0', port: 4001 };
}

class VRFResolver {
  constructor(seed) {
    this.seed = seed;
  }

  getDeterministicPriority(taskId, epoch, peerId) {
    const input = `${this.seed}:${taskId}:${epoch}:${peerId}`;
    const hash = crypto.createHash('sha256').update(input).digest();
    return hash.readUInt32BE(0);
  }

  getEpochSeed(epoch) {
    return crypto.createHash('sha256').update(`${this.seed}:${epoch}`).digest('hex');
  }
}

class GossipSubNetwork {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.logger = createLogger('p2p-gossip-network');
    this.peers = new Map();
    this.peerSockets = new Map();
    this.taskClaims = new Map();
    this.vrf = new VRFResolver(this.config.vrfSeed);
    this.currentEpoch = Math.floor(Date.now() / this.config.epochDurationMs);
    this.isRunning = false;

    // Cryptographic node identity (Ed25519 static identity and X25519 static DH)
    this.ed25519Keypair = this.config.ed25519Keypair || crypto.generateKeyPairSync('ed25519');
    this.staticDhKeypair = this.config.staticDhKeypair || crypto.generateKeyPairSync('x25519');
    this.rawEd25519Pub = exportRawPublicKey(this.ed25519Keypair.publicKey);
    this.peerId = this.config.peerId || this.rawEd25519Pub.toString('hex');

    this.allowedPeerIdentities = this.config.allowedPeerIdentities
      ? new Set(this.config.allowedPeerIdentities)
      : null;

    this.server = null;
    this.actualPort = null;
    this.incomingSockets = new Set();
  }

  async start() {
    this.isRunning = true;
    this.logger.info('Starting P2P GossipSub network', {
      peerId: this.peerId,
      listenAddr: this.config.listenAddr,
    });

    if (this.config.enableTcpMesh) {
      await this.startTcpServer();
      if (Array.isArray(this.config.bootstrapPeers)) {
        for (const peerAddr of this.config.bootstrapPeers) {
          this.connectToPeer(peerAddr).catch((err) => {
            this.logger.debug('Failed to connect to bootstrap peer', { peerAddr, error: err.message });
          });
        }
      }
    }

    this.heartbeatTimer = setInterval(() => {
      this.heartbeat();
    }, this.config.heartbeatIntervalMs);

    this.epochTimer = setInterval(() => {
      this.advanceEpoch();
    }, this.config.epochDurationMs);
  }

  startTcpServer() {
    return new Promise((resolve) => {
      const { host, port } = parseMultiaddr(this.config.listenAddr);

      this.server = net.createServer((socket) => {
        this.handleIncomingConnection(socket);
      });

      this.server.on('error', (err) => {
        this.logger.error('TCP server error', { error: err.message });
      });

      this.server.listen(port, host, () => {
        const addr = this.server.address();
        this.actualPort = typeof addr === 'object' && addr ? addr.port : port;
        this.logger.info('TCP Gossip mesh listening', { host, port: this.actualPort });
        resolve(this.actualPort);
      });
    });
  }

  async connectToPeer(peerAddr) {
    if (!this.isRunning) return null;
    const { host, port } = parseMultiaddr(peerAddr);

    return new Promise((resolve, reject) => {
      const socket = net.connect({ host, port }, async () => {
        try {
          const handshake = new NoiseHandshake({
            isInitiator: true,
            ed25519Keypair: this.ed25519Keypair,
            staticDhKeypair: this.staticDhKeypair,
            allowedPeerIdentities: this.allowedPeerIdentities,
          });

          // Send Message 1
          const msg1 = handshake.createMessage1();
          this.writeLengthPrefixedFrame(socket, msg1);

          let buffer = Buffer.alloc(0);

          const onData = (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);

            while (buffer.length >= 4) {
              const frameLen = buffer.readUInt32BE(0);
              if (buffer.length < 4 + frameLen) break;

              const frame = buffer.subarray(4, 4 + frameLen);
              buffer = buffer.subarray(4 + frameLen);

              if (!handshake.isComplete) {
                if (handshake.state === 'INITIATOR_WAIT_MSG2') {
                  handshake.processMessage2(frame);
                  const msg3 = handshake.createMessage3();
                  this.writeLengthPrefixedFrame(socket, msg3);

                  // Handshake completed!
                  const peerNodeId = exportRawPublicKey(handshake.peerEd25519Pub).toString('hex');
                  this.registerSecurePeer(peerNodeId, socket, handshake.session);
                  resolve(peerNodeId);
                }
              } else {
                // Application gossip message
                this.handleEncryptedData(socket, handshake.session, frame);
              }
            }
          };

          socket.on('data', onData);
          socket.on('error', (err) => {
            this.logger.debug('Peer socket error', { peerAddr, error: err.message });
          });
          socket.on('close', () => {
            this.cleanupSocket(socket);
          });
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      });

      socket.on('error', (err) => {
        reject(err);
      });
    });
  }

  handleIncomingConnection(socket) {
    this.incomingSockets.add(socket);
    let handshake = null;
    let buffer = Buffer.alloc(0);

    try {
      handshake = new NoiseHandshake({
        isInitiator: false,
        ed25519Keypair: this.ed25519Keypair,
        staticDhKeypair: this.staticDhKeypair,
        allowedPeerIdentities: this.allowedPeerIdentities,
      });
    } catch (_err) {
      socket.destroy();
      return;
    }

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);

      try {
        while (buffer.length >= 4) {
          const frameLen = buffer.readUInt32BE(0);
          if (buffer.length < 4 + frameLen) break;

          const frame = buffer.subarray(4, 4 + frameLen);
          buffer = buffer.subarray(4 + frameLen);

          if (!handshake.isComplete) {
            if (handshake.state === 'RESPONDER_WAIT_MSG1') {
              handshake.processMessage1(frame);
              const msg2 = handshake.createMessage2();
              this.writeLengthPrefixedFrame(socket, msg2);
            } else if (handshake.state === 'RESPONDER_WAIT_MSG3') {
              handshake.processMessage3(frame);
              // Handshake complete on responder
              const peerNodeId = exportRawPublicKey(handshake.peerEd25519Pub).toString('hex');
              this.registerSecurePeer(peerNodeId, socket, handshake.session);
            }
          } else {
            this.handleEncryptedData(socket, handshake.session, frame);
          }
        }
      } catch (err) {
        this.logger.warn('Handshake failed or unauthorized peer rejected', {
          error: err.message,
        });
        socket.destroy();
      }
    });

    socket.on('error', () => {
      this.cleanupSocket(socket);
    });

    socket.on('close', () => {
      this.cleanupSocket(socket);
    });
  }

  writeLengthPrefixedFrame(socket, payload) {
    if (socket && !socket.destroyed) {
      const header = Buffer.alloc(4);
      header.writeUInt32BE(payload.length, 0);
      socket.write(Buffer.concat([header, payload]));
    }
  }

  registerSecurePeer(peerId, socket, noiseSession) {
    this.addPeer(peerId, { secure: true, transport: 'noise_tcp' });
    this.peerSockets.set(peerId, { socket, noiseSession });
    socket._peerId = peerId;
    this.logger.info('Secure peer connected with forward-secret channel', { peerId });
  }

  cleanupSocket(socket) {
    this.incomingSockets.delete(socket);
    if (socket._peerId) {
      this.peerSockets.delete(socket._peerId);
      this.removePeer(socket._peerId);
    }
  }

  handleEncryptedData(socket, noiseSession, ciphertext) {
    try {
      const plaintext = noiseSession.decrypt(ciphertext);
      const message = JSON.parse(plaintext.toString('utf8'));
      this.handleGossipMessage(message);
    } catch (err) {
      this.logger.warn('Failed to decrypt gossip frame; dropping corrupted packet', {
        error: err.message,
      });
    }
  }

  async stop() {
    this.isRunning = false;
    clearInterval(this.heartbeatTimer);
    clearInterval(this.epochTimer);

    for (const s of this.incomingSockets) {
      try {
        s.destroy();
      } catch (_e) {
        // ignore socket cleanup error
      }
    }
    this.incomingSockets.clear();

    for (const [, entry] of this.peerSockets) {
      if (entry.socket && !entry.socket.destroyed) {
        entry.socket.destroy();
      }
    }
    this.peerSockets.clear();

    if (this.server) {
      try {
        this.server.close();
      } catch (_e) {
        // ignore server close error
      }
      this.server = null;
    }

    this.peers.clear();
    this.taskClaims.clear();
    this.logger.info('P2P network stopped');
  }

  heartbeat() {
    const now = Date.now();
    for (const [peerId, peer] of this.peers) {
      if (now - peer.lastSeen > this.config.heartbeatIntervalMs * 3) {
        this.peers.delete(peerId);
        const entry = this.peerSockets.get(peerId);
        if (entry && entry.socket) entry.socket.destroy();
        this.peerSockets.delete(peerId);
        this.logger.debug('Peer timed out', { peerId });
      }
    }
  }

  advanceEpoch() {
    this.currentEpoch++;
    this.taskClaims.clear();
    this.logger.info('Epoch advanced', {
      epoch: this.currentEpoch,
      seed: this.vrf.getEpochSeed(this.currentEpoch).slice(0, 16),
    });
  }

  addPeer(peerId, metadata = {}) {
    if (this.peers.size >= this.config.maxPeers) {
      this.logger.warn('Max peers reached', { maxPeers: this.config.maxPeers });
      return false;
    }

    this.peers.set(peerId, {
      id: peerId,
      lastSeen: Date.now(),
      metadata,
      activeTasks: 0,
    });
    this.logger.debug('Peer added', { peerId });
    return true;
  }

  removePeer(peerId) {
    this.peers.delete(peerId);
    this.logger.debug('Peer removed', { peerId });
  }

  claimTask(taskId) {
    const existingClaim = this.taskClaims.get(taskId);
    if (existingClaim) {
      this.logger.debug('Task already claimed', {
        taskId,
        claimant: existingClaim.peerId,
      });
      return { claimed: false, claimant: existingClaim.peerId };
    }

    const priority = this.vrf.getDeterministicPriority(
      taskId,
      this.currentEpoch,
      this.peerId
    );

    this.taskClaims.set(taskId, {
      peerId: this.peerId,
      priority,
      timestamp: Date.now(),
      epoch: this.currentEpoch,
    });

    this.logger.info('Task claimed', { taskId, priority });
    return { claimed: true, priority };
  }

  resolveConflict(taskId, competingClaims) {
    if (competingClaims.length === 0) {
      return null;
    }

    const sortedClaims = competingClaims.sort((a, b) => b.priority - a.priority);
    const winner = sortedClaims[0];

    this.logger.info('Conflict resolved', {
      taskId,
      winner: winner.peerId,
      priority: winner.priority,
      totalClaims: competingClaims.length,
    });

    return winner;
  }

  broadcastGossip(message) {
    const gossipMessage = {
      type: 'task_claim',
      peerId: this.peerId,
      epoch: this.currentEpoch,
      timestamp: Date.now(),
      ...message,
    };

    this.logger.debug('Broadcasting gossip', {
      type: gossipMessage.type,
      taskId: message.taskId,
    });

    // Send encrypted frame to every connected TCP peer
    const serialized = Buffer.from(JSON.stringify(gossipMessage), 'utf8');
    for (const [peerId, entry] of this.peerSockets) {
      if (entry.socket && !entry.socket.destroyed && entry.noiseSession) {
        try {
          const frame = entry.noiseSession.encodeFrame(serialized);
          entry.socket.write(frame);
        } catch (err) {
          this.logger.warn('Failed to send encrypted gossip to peer', { peerId, error: err.message });
        }
      }
    }

    return gossipMessage;
  }

  handleGossipMessage(message) {
    if (!message || message.peerId === this.peerId) {
      return null;
    }

    this.addPeer(message.peerId, { lastGossip: message.timestamp });

    switch (message.type) {
      case 'task_claim':
        return this.handleTaskClaim(message);
      case 'task_release':
        return this.handleTaskRelease(message);
      case 'heartbeat':
        return this.handleHeartbeat(message);
      default:
        this.logger.warn('Unknown gossip message type', { type: message.type });
        return null;
    }
  }

  handleTaskClaim(message) {
    const { taskId, peerId, priority } = message;

    if (!this.taskClaims.has(taskId)) {
      this.taskClaims.set(taskId, {
        peerId,
        priority,
        timestamp: message.timestamp,
        epoch: message.epoch,
      });
      return { accepted: true };
    }

    const existing = this.taskClaims.get(taskId);
    if (priority > existing.priority) {
      this.taskClaims.set(taskId, {
        peerId,
        priority,
        timestamp: message.timestamp,
        epoch: message.epoch,
      });
      return { accepted: true, replaced: existing.peerId };
    }

    return { accepted: false, reason: 'lower_priority' };
  }

  handleTaskRelease(message) {
    const { taskId, peerId } = message;
    const claim = this.taskClaims.get(taskId);

    if (claim && claim.peerId === peerId) {
      this.taskClaims.delete(taskId);
      return { released: true };
    }

    return { released: false, reason: 'not_claimant' };
  }

  handleHeartbeat(_message) {
    return { acknowledged: true, peerId: this.peerId };
  }

  getNetworkState() {
    return {
      peerId: this.peerId,
      epoch: this.currentEpoch,
      epochSeed: this.vrf.getEpochSeed(this.currentEpoch).slice(0, 16),
      connectedPeers: this.peers.size,
      activeClaims: this.taskClaims.size,
      claims: Object.fromEntries(this.taskClaims),
    };
  }
}

module.exports = {
  GossipSubNetwork,
  VRFResolver,
  DEFAULT_CONFIG,
  NoiseHandshake,
  NoiseSession,
};
