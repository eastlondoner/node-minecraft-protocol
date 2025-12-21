'use strict'

const EventEmitter = require('events').EventEmitter
const crypto = require('crypto')
const zlib = require('zlib')
const { promisify } = require('util')

const [readVarInt, writeVarInt, sizeOfVarInt] = require('protodef').types.varint
const { createSerializer, createDeserializer } = require('./transforms/serializer')
const states = require('./states')

const debug = require('debug')('minecraft-protocol')
const debugSkip = process.env.DEBUG_SKIP?.split(',') ?? []

const deflateAsync = promisify(zlib.deflate)
const inflateAsync = promisify(zlib.inflate)

const LEGACY_PING_PACKET_ID = 0xfe
const CLOSE_TIMEOUT = 30_000

/**
 * Bun-native Minecraft protocol client.
 * Uses Bun.connect directly instead of Node.js streams for better performance.
 */
class Client extends EventEmitter {
  constructor(isServer, version, customPackets, hideErrors = false) {
    super()
    this.customPackets = customPackets
    this.version = version
    this.isServer = !!isServer
    this.hideErrors = hideErrors
    this.ended = true
    this.latency = 0
    this.closeTimer = null
    
    // Bun socket handle
    this._socket = null
    
    // Incoming data buffer
    this._readBuffer = Buffer.alloc(0)
    this._recognizeLegacyPing = false
    
    // Compression threshold (-1 = disabled)
    this._compressionThreshold = -1
    
    // Encryption (AES-128-CFB8)
    this._cipher = null
    this._decipher = null
    
    // Packet parsing
    this.packetsToParse = {}
    
    const mcData = require('minecraft-data')(version)
    this._supportFeature = mcData.supportFeature
    this._hasBundlePacket = mcData.supportFeature('hasBundlePacket')
    this._mcBundle = []
    
    this.state = states.HANDSHAKING
  }

  // Expose socket for compatibility
  get socket() {
    return this._socket
  }

  get state() {
    return this._protocolState
  }

  set state(newState) {
    const oldState = this._protocolState
    this._protocolState = newState
    this._recognizeLegacyPing = newState === states.HANDSHAKING
    
    this._serializer = createSerializer({
      isServer: this.isServer,
      version: this.version,
      state: newState,
      customPackets: this.customPackets
    })
    
    this._deserializer = createDeserializer({
      isServer: this.isServer,
      version: this.version,
      state: newState,
      packetsToParse: this.packetsToParse,
      customPackets: this.customPackets,
      noErrorLogging: this.hideErrors
    })
    
    this.emit('state', newState, oldState)
  }

  get compressionThreshold() {
    return this._compressionThreshold
  }

  set compressionThreshold(threshold) {
    this._compressionThreshold = threshold
  }

  setCompressionThreshold(threshold) {
    this._compressionThreshold = threshold
  }

  /**
   * Connect to server using Bun's native TCP
   */
  connect(port, host) {
    if (!port || !host) {
      throw new Error('port and host are required')
    }
    
    this.ended = false
    const self = this
    
    Bun.connect({
      hostname: host,
      port: port,
      socket: {
        open(socket) {
          self._socket = socket
          self.emit('connect')
        },
        
        data(socket, data) {
          self._handleIncomingData(Buffer.from(data))
        },
        
        close() {
          self._handleClose()
        },
        
        error(socket, error) {
          self.emit('error', error)
          self._handleClose()
        },
        
        connectError(socket, error) {
          self.emit('error', error)
          self._handleClose()
        },
      },
    }).catch(err => {
      self.emit('error', err)
      self._handleClose()
    })
  }

  /**
   * Process incoming data: decrypt → split → decompress → deserialize
   */
  _handleIncomingData(data) {
    // Decrypt if encryption enabled
    if (this._decipher) {
      data = Buffer.from(this._decipher.update(data))
    }
    
    // Append to buffer and process packets
    this._readBuffer = Buffer.concat([this._readBuffer, data])
    this._processPackets()
  }

  /**
   * Extract complete packets from buffer
   */
  _processPackets() {
    // Legacy ping special case
    if (this._recognizeLegacyPing && this._readBuffer[0] === LEGACY_PING_PACKET_ID) {
      const header = Buffer.alloc(sizeOfVarInt(LEGACY_PING_PACKET_ID))
      writeVarInt(LEGACY_PING_PACKET_ID, header, 0)
      let payload = this._readBuffer.slice(1)
      if (payload.length === 0) payload = Buffer.from('\0')
      this._processPacket(Buffer.concat([header, payload]))
      this._readBuffer = Buffer.alloc(0)
      return
    }

    let offset = 0
    
    while (offset < this._readBuffer.length) {
      let packetLength, headerSize
      try {
        const result = readVarInt(this._readBuffer, offset)
        packetLength = result.value
        headerSize = result.size
      } catch (e) {
        if (e.partialReadError) break
        throw e
      }
      
      // Wait for complete packet
      if (this._readBuffer.length < offset + headerSize + packetLength) {
        break
      }
      
      const packetData = this._readBuffer.slice(
        offset + headerSize,
        offset + headerSize + packetLength
      )
      offset += headerSize + packetLength
      
      this._processPacket(packetData)
    }
    
    // Trim processed data
    if (offset > 0) {
      this._readBuffer = this._readBuffer.slice(offset)
    }
  }

  /**
   * Decompress and deserialize a single packet
   */
  async _processPacket(data) {
    try {
      // Handle compression
      if (this._compressionThreshold >= 0) {
        const { size, value: uncompressedLength } = readVarInt(data, 0)
        
        if (uncompressedLength === 0) {
          data = data.slice(size)
        } else {
          data = await inflateAsync(data.slice(size), { finishFlush: 2 })
        }
      }
      
      // Deserialize
      const parsed = this._deserializer.parsePacketBuffer(data)
      const name = parsed.data.name
      const params = parsed.data.params
      
      if (debug.enabled && !debugSkip.includes(name)) {
        debug('read packet ' + this._protocolState + '.' + name)
      }
      
      const packet = {
        data: params,
        metadata: { name, state: this._protocolState },
        buffer: data,
        fullBuffer: data
      }
      
      // Bundle handling
      if (this._hasBundlePacket && name === 'bundle_delimiter') {
        if (this._mcBundle.length) {
          this._mcBundle.forEach(p => this._emitPacket(p))
          this._emitPacket(packet)
          this._mcBundle = []
        } else {
          this._mcBundle.push(packet)
        }
      } else if (this._mcBundle.length) {
        this._mcBundle.push(packet)
        if (this._mcBundle.length > 32) {
          this._mcBundle.forEach(p => this._emitPacket(p))
          this._mcBundle = []
          this._hasBundlePacket = false
        }
      } else {
        this._emitPacket(packet)
      }
    } catch (e) {
      if (!this.hideErrors) {
        console.error('Packet parse error:', e)
      }
      this.emit('error', e)
    }
  }

  _emitPacket(packet) {
    this.emit('packet', packet.data, packet.metadata, packet.buffer, packet.fullBuffer)
    this.emit(packet.metadata.name, packet.data, packet.metadata)
    this.emit('raw.' + packet.metadata.name, packet.buffer, packet.metadata)
    this.emit('raw', packet.buffer, packet.metadata)
  }

  /**
   * Send a packet: serialize → compress → frame → encrypt → send
   */
  async write(name, params) {
    if (this.ended || !this._socket) return
    
    if (debug.enabled && !debugSkip.includes(name)) {
      debug('writing packet ' + this._protocolState + '.' + name)
    }
    
    // Serialize
    let payload = this._serializer.createPacketBuffer({ name, params })
    
    // Compress if enabled
    if (this._compressionThreshold >= 0) {
      if (payload.length >= this._compressionThreshold) {
        const compressed = await deflateAsync(payload)
        const header = Buffer.alloc(sizeOfVarInt(payload.length))
        writeVarInt(payload.length, header, 0)
        payload = Buffer.concat([header, compressed])
      } else {
        const header = Buffer.alloc(sizeOfVarInt(0))
        writeVarInt(0, header, 0)
        payload = Buffer.concat([header, payload])
      }
    }
    
    // Frame with length prefix
    const lengthPrefix = Buffer.alloc(sizeOfVarInt(payload.length))
    writeVarInt(payload.length, lengthPrefix, 0)
    let frame = Buffer.concat([lengthPrefix, payload])
    
    // Encrypt if enabled
    if (this._cipher) {
      frame = Buffer.from(this._cipher.update(frame))
    }
    
    // Send
    this._socket.write(frame)
  }

  writeBundle(packets) {
    if (this._hasBundlePacket) this.write('bundle_delimiter', {})
    for (const [name, params] of packets) this.write(name, params)
    if (this._hasBundlePacket) this.write('bundle_delimiter', {})
  }

  writeRaw(buffer) {
    if (this.ended || !this._socket) return
    
    if (this._cipher) {
      buffer = Buffer.from(this._cipher.update(buffer))
    }
    this._socket.write(buffer)
  }

  setEncryption(sharedSecret) {
    this._cipher = crypto.createCipheriv('aes-128-cfb8', sharedSecret, sharedSecret)
    this._decipher = crypto.createDecipheriv('aes-128-cfb8', sharedSecret, sharedSecret)
  }

  _handleClose() {
    if (this.ended) return
    this.ended = true
    clearTimeout(this.closeTimer)
    this._socket = null
    this.emit('end', this._endReason || 'socketClosed')
  }

  end(reason) {
    this._endReason = reason
    if (this._socket) {
      this._socket.end()
      this.closeTimer = setTimeout(() => {
        if (this._socket) {
          this._socket.end()
          this._socket = null
        }
      }, CLOSE_TIMEOUT)
    }
  }
}

module.exports = Client
