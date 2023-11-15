(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.CorestoreModule = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
const { Pull, Push, HEADERBYTES, KEYBYTES, ABYTES } = require('sodium-secretstream')
const sodium = require('sodium-javascript')
const crypto = require('hypercore-crypto')
const { Duplex, Writable, getStreamError } = require('streamx')
const b4a = require('b4a')
const Timeout = require('timeout-refresh')
const Bridge = require('./lib/bridge')
const Handshake = require('./lib/handshake')

const IDHEADERBYTES = HEADERBYTES + 32
const [NS_INITIATOR, NS_RESPONDER] = crypto.namespace('hyperswarm/secret-stream', 2)

module.exports = class NoiseSecretStream extends Duplex {
  constructor (isInitiator, rawStream, opts = {}) {
    super({ mapWritable: toBuffer })

    if (typeof isInitiator !== 'boolean') {
      throw new Error('isInitiator should be a boolean')
    }

    this.noiseStream = this
    this.isInitiator = isInitiator
    this.rawStream = null

    this.publicKey = opts.publicKey || null
    this.remotePublicKey = opts.remotePublicKey || null
    this.handshakeHash = null

    // pointer for upstream to set data here if they want
    this.userData = null

    let openedDone = null
    this.opened = new Promise((resolve) => { openedDone = resolve })

    // unwrapped raw stream
    this._rawStream = null

    // handshake state
    this._handshake = null
    this._handshakePattern = opts.pattern || null
    this._handshakeDone = null

    // message parsing state
    this._state = 0
    this._len = 0
    this._tmp = 1
    this._message = null

    this._openedDone = openedDone
    this._startDone = null
    this._drainDone = null
    this._outgoingPlain = null
    this._outgoingWrapped = null
    this._utp = null
    this._setup = true
    this._ended = 2
    this._encrypt = null
    this._decrypt = null
    this._timeout = null
    this._timeoutMs = 0
    this._keepAlive = null
    this._keepAliveMs = 0

    if (opts.autoStart !== false) this.start(rawStream, opts)

    // wiggle it to trigger open immediately (TODO add streamx option for this)
    this.resume()
    this.pause()
  }

  static keyPair (seed) {
    return Handshake.keyPair(seed)
  }

  static id (handshakeHash, isInitiator, id) {
    return streamId(handshakeHash, isInitiator, id)
  }

  setTimeout (ms) {
    if (!ms) ms = 0

    this._clearTimeout()
    this._timeoutMs = ms

    if (!ms || this.rawStream === null) return

    this._timeout = Timeout.once(ms, destroyTimeout, this)
    this._timeout.unref()
  }

  setKeepAlive (ms) {
    if (!ms) ms = 0

    this._keepAliveMs = ms

    if (!ms || this.rawStream === null) return

    this._keepAlive = Timeout.on(ms, sendKeepAlive, this)
    this._keepAlive.unref()
  }

  start (rawStream, opts = {}) {
    if (rawStream) {
      this.rawStream = rawStream
      this._rawStream = rawStream
      if (typeof this.rawStream.setContentSize === 'function') {
        this._utp = rawStream
      }
    } else {
      this.rawStream = new Bridge(this)
      this._rawStream = this.rawStream.reverse
    }

    this.rawStream.on('error', this._onrawerror.bind(this))
    this.rawStream.on('close', this._onrawclose.bind(this))

    this._startHandshake(opts.handshake, opts.keyPair || null)
    this._continueOpen(null)

    if (this.destroying) return

    if (opts.data) this._onrawdata(opts.data)
    if (opts.ended) this._onrawend()

    if (this._keepAliveMs > 0 && this._keepAlive === null) {
      this.setKeepAlive(this._keepAliveMs)
    }

    if (this._timeoutMs > 0 && this._timeout === null) {
      this.setTimeout(this._timeoutMs)
    }
  }

  async flush () {
    if ((await this.opened) === false) return false
    if ((await Writable.drained(this)) === false) return false
    if (this.destroying) return false

    if (this.rawStream !== null && this.rawStream.flush) {
      return await this.rawStream.flush()
    }

    return true
  }

  _continueOpen (err) {
    if (err) this.destroy(err)
    if (this._startDone === null) return
    const done = this._startDone
    this._startDone = null
    this._open(done)
  }

  _onkeypairpromise (p) {
    const self = this
    const cont = this._continueOpen.bind(this)

    p.then(onkeypair, cont)

    function onkeypair (kp) {
      self._onkeypair(kp)
      cont(null)
    }
  }

  _onkeypair (keyPair) {
    const pattern = this._handshakePattern || 'XX'
    const remotePublicKey = this.remotePublicKey

    this._handshake = new Handshake(this.isInitiator, keyPair, remotePublicKey, pattern)
    this.publicKey = this._handshake.keyPair.publicKey
  }

  _startHandshake (handshake, keyPair) {
    if (handshake) {
      const { tx, rx, hash, publicKey, remotePublicKey } = handshake
      this._setupSecretStream(tx, rx, hash, publicKey, remotePublicKey)
      return
    }

    if (!keyPair) keyPair = Handshake.keyPair()

    if (typeof keyPair.then === 'function') {
      this._onkeypairpromise(keyPair)
    } else {
      this._onkeypair(keyPair)
    }
  }

  _onrawerror (err) {
    this.destroy(err)
  }

  _onrawclose () {
    if (this._ended !== 0) this.destroy()
  }

  _onrawdata (data) {
    let offset = 0

    if (this._timeout !== null) {
      this._timeout.refresh()
    }

    do {
      switch (this._state) {
        case 0: {
          while (this._tmp !== 0x1000000 && offset < data.length) {
            const v = data[offset++]
            this._len += this._tmp * v
            this._tmp *= 256
          }

          if (this._tmp === 0x1000000) {
            this._tmp = 0
            this._state = 1
            const unprocessed = data.length - offset
            if (unprocessed < this._len && this._utp !== null) this._utp.setContentSize(this._len - unprocessed)
          }

          break
        }

        case 1: {
          const missing = this._len - this._tmp
          const end = missing + offset

          if (this._message === null && end <= data.length) {
            this._message = data.subarray(offset, end)
            offset += missing
            this._incoming()
            break
          }

          const unprocessed = data.length - offset

          if (this._message === null) {
            this._message = b4a.allocUnsafe(this._len)
          }

          b4a.copy(data, this._message, this._tmp, offset)
          this._tmp += unprocessed

          if (end <= data.length) {
            offset += missing
            this._incoming()
          } else {
            offset += unprocessed
          }

          break
        }
      }
    } while (offset < data.length && !this.destroying)
  }

  _onrawend () {
    this._ended--
    this.push(null)
  }

  _onrawdrain () {
    const drain = this._drainDone
    if (drain === null) return
    this._drainDone = null
    drain()
  }

  _read (cb) {
    this.rawStream.resume()
    cb(null)
  }

  _incoming () {
    const message = this._message

    this._state = 0
    this._len = 0
    this._tmp = 1
    this._message = null

    if (this._setup === true) {
      if (this._handshake) {
        this._onhandshakert(this._handshake.recv(message))
      } else {
        if (message.byteLength !== IDHEADERBYTES) {
          this.destroy(new Error('Invalid header message received'))
          return
        }

        const remoteId = message.subarray(0, 32)
        const expectedId = streamId(this.handshakeHash, !this.isInitiator)
        const header = message.subarray(32)

        if (!b4a.equals(expectedId, remoteId)) {
          this.destroy(new Error('Invalid header received'))
          return
        }

        this._decrypt.init(header)
        this._setup = false // setup is now done
      }
      return
    }

    if (message.length < ABYTES) {
      this.destroy(new Error('Invalid message received'))
      return
    }

    const plain = message.subarray(1, message.byteLength - ABYTES + 1)

    try {
      this._decrypt.next(message, plain)
    } catch (err) {
      this.destroy(err)
      return
    }

    // If keep alive is selective, eat the empty buffers (ie assume the other side has it enabled also)
    if (plain.byteLength === 0 && this._keepAliveMs !== 0) return

    if (this.push(plain) === false) {
      this.rawStream.pause()
    }
  }

  _onhandshakert (h) {
    if (this._handshakeDone === null) return

    if (h !== null) {
      if (h.data) this._rawStream.write(h.data)
      if (!h.tx) return
    }

    const done = this._handshakeDone
    const publicKey = this._handshake.keyPair.publicKey

    this._handshakeDone = null
    this._handshake = null

    if (h === null) return done(new Error('Noise handshake failed'))

    this._setupSecretStream(h.tx, h.rx, h.hash, publicKey, h.remotePublicKey)
    this._resolveOpened(true)
    done(null)
  }

  _setupSecretStream (tx, rx, handshakeHash, publicKey, remotePublicKey) {
    const buf = b4a.allocUnsafe(3 + IDHEADERBYTES)
    writeUint24le(IDHEADERBYTES, buf)

    this._encrypt = new Push(tx.subarray(0, KEYBYTES), undefined, buf.subarray(3 + 32))
    this._decrypt = new Pull(rx.subarray(0, KEYBYTES))

    this.publicKey = publicKey
    this.remotePublicKey = remotePublicKey
    this.handshakeHash = handshakeHash

    const id = buf.subarray(3, 3 + 32)
    streamId(handshakeHash, this.isInitiator, id)

    this.emit('handshake')
    // if rawStream is a bridge, also emit it there
    if (this.rawStream !== this._rawStream) this.rawStream.emit('handshake')

    if (this.destroying) return

    this._rawStream.write(buf)
  }

  _open (cb) {
    // no autostart or no handshake yet
    if (this._rawStream === null || (this._handshake === null && this._encrypt === null)) {
      this._startDone = cb
      return
    }

    this._rawStream.on('data', this._onrawdata.bind(this))
    this._rawStream.on('end', this._onrawend.bind(this))
    this._rawStream.on('drain', this._onrawdrain.bind(this))

    if (this._encrypt !== null) {
      this._resolveOpened(true)
      return cb(null)
    }

    this._handshakeDone = cb

    if (this.isInitiator) this._onhandshakert(this._handshake.send())
  }

  _predestroy () {
    if (this.rawStream) {
      const error = getStreamError(this)
      this.rawStream.destroy(error)
    }

    if (this._startDone !== null) {
      const done = this._startDone
      this._startDone = null
      done(new Error('Stream destroyed'))
    }

    if (this._handshakeDone !== null) {
      const done = this._handshakeDone
      this._handshakeDone = null
      done(new Error('Stream destroyed'))
    }

    if (this._drainDone !== null) {
      const done = this._drainDone
      this._drainDone = null
      done(new Error('Stream destroyed'))
    }
  }

  _write (data, cb) {
    let wrapped = this._outgoingWrapped

    if (data !== this._outgoingPlain) {
      wrapped = b4a.allocUnsafe(data.byteLength + 3 + ABYTES)
      wrapped.set(data, 4)
    } else {
      this._outgoingWrapped = this._outgoingPlain = null
    }

    writeUint24le(wrapped.byteLength - 3, wrapped)
    // offset 4 so we can do it in-place
    this._encrypt.next(wrapped.subarray(4, 4 + data.byteLength), wrapped.subarray(3))

    if (this._keepAlive !== null) this._keepAlive.refresh()

    if (this._rawStream.write(wrapped) === false) {
      this._drainDone = cb
    } else {
      cb(null)
    }
  }

  _final (cb) {
    this._clearKeepAlive()
    this._ended--
    this._rawStream.end()
    cb(null)
  }

  _resolveOpened (val) {
    if (this._openedDone !== null) {
      const opened = this._openedDone
      this._openedDone = null
      opened(val)
      if (val) this.emit('connect')
    }
  }

  _clearTimeout () {
    if (this._timeout === null) return
    this._timeout.destroy()
    this._timeout = null
    this._timeoutMs = 0
  }

  _clearKeepAlive () {
    if (this._keepAlive === null) return
    this._keepAlive.destroy()
    this._keepAlive = null
    this._keepAliveMs = 0
  }

  _destroy (cb) {
    this._clearKeepAlive()
    this._clearTimeout()
    this._resolveOpened(false)
    cb(null)
  }

  alloc (len) {
    const buf = b4a.allocUnsafe(len + 3 + ABYTES)
    this._outgoingWrapped = buf
    this._outgoingPlain = buf.subarray(4, buf.byteLength - ABYTES + 1)
    return this._outgoingPlain
  }
}

function writeUint24le (n, buf) {
  buf[0] = (n & 255)
  buf[1] = (n >>> 8) & 255
  buf[2] = (n >>> 16) & 255
}

function streamId (handshakeHash, isInitiator, out = b4a.allocUnsafe(32)) {
  sodium.crypto_generichash(out, isInitiator ? NS_INITIATOR : NS_RESPONDER, handshakeHash)
  return out
}

function toBuffer (data) {
  return typeof data === 'string' ? b4a.from(data) : data
}

function destroyTimeout () {
  this.destroy(new Error('Stream timed out'))
}

function sendKeepAlive () {
  const empty = this.alloc(0)
  this.write(empty)
}

},{"./lib/bridge":2,"./lib/handshake":3,"b4a":4,"hypercore-crypto":26,"sodium-javascript":97,"sodium-secretstream":103,"streamx":128,"timeout-refresh":129}],2:[function(require,module,exports){
const { Duplex, Writable } = require('streamx')

class ReversePassThrough extends Duplex {
  constructor (s) {
    super()
    this._stream = s
    this._ondrain = null
  }

  _write (data, cb) {
    if (this._stream.push(data) === false) {
      this._stream._ondrain = cb
    } else {
      cb(null)
    }
  }

  _final (cb) {
    this._stream.push(null)
    cb(null)
  }

  _read (cb) {
    const ondrain = this._ondrain
    this._ondrain = null
    if (ondrain) ondrain()
    cb(null)
  }
}

module.exports = class Bridge extends Duplex {
  constructor (noiseStream) {
    super()

    this.noiseStream = noiseStream

    this._ondrain = null
    this.reverse = new ReversePassThrough(this)
  }

  get publicKey () {
    return this.noiseStream.publicKey
  }

  get remotePublicKey () {
    return this.noiseStream.remotePublicKey
  }

  get handshakeHash () {
    return this.noiseStream.handshakeHash
  }

  flush () {
    return Writable.drained(this)
  }

  _read (cb) {
    const ondrain = this._ondrain
    this._ondrain = null
    if (ondrain) ondrain()
    cb(null)
  }

  _write (data, cb) {
    if (this.reverse.push(data) === false) {
      this.reverse._ondrain = cb
    } else {
      cb(null)
    }
  }

  _final (cb) {
    this.reverse.push(null)
    cb(null)
  }
}

},{"streamx":128}],3:[function(require,module,exports){
const sodium = require('sodium-javascript')
///const curve = require('noise-curve-ed')
const Noise = require('noise-handshake')
const b4a = require('b4a')

const EMPTY = b4a.alloc(0)

module.exports = class Handshake {
  constructor (isInitiator, keyPair, remotePublicKey, pattern) {
    this.isInitiator = isInitiator
    this.keyPair = keyPair
    this.noise = new Noise(pattern, isInitiator)
    this.noise.initialise(EMPTY)
    this.destroyed = false
  }

  static keyPair (seed) {
    const publicKey = b4a.alloc(32)
    const secretKey = b4a.alloc(64)
    if (seed) sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
    else sodium.crypto_sign_keypair(publicKey, secretKey)
    return { publicKey, secretKey }
  }

  recv (data) {
    try {
      this.noise.recv(data)
      if (this.noise.complete) return this._return(null)
      return this.send()
    } catch {
      this.destroy()
      return null
    }
  }

  // note that the data returned here is framed so we don't have to do an extra copy
  // when sending it...
  send () {
    try {
      const data = this.noise.send()
      const wrap = b4a.allocUnsafe(data.byteLength + 3)

      writeUint24le(data.byteLength, wrap)
      wrap.set(data, 3)

      return this._return(wrap)
    } catch {
      this.destroy()
      return null
    }
  }

  destroy () {
    if (this.destroyed) return
    this.destroyed = true
  }

  _return (data) {
    const tx = this.noise.complete ? b4a.toBuffer(this.noise.tx) : null
    const rx = this.noise.complete ? b4a.toBuffer(this.noise.rx) : null
    const hash = this.noise.complete ? b4a.toBuffer(this.noise.hash) : null
    const remotePublicKey = this.noise.complete ? b4a.toBuffer(this.noise.rs) : null

    return {
      data,
      remotePublicKey,
      hash,
      tx,
      rx
    }
  }
}

function writeUint24le (n, buf) {
  buf[0] = (n & 255)
  buf[1] = (n >>> 8) & 255
  buf[2] = (n >>> 16) & 255
}

},{"b4a":4,"noise-handshake":56,"sodium-javascript":97}],4:[function(require,module,exports){
const ascii = require('./lib/ascii')
const base64 = require('./lib/base64')
const hex = require('./lib/hex')
const utf8 = require('./lib/utf8')
const utf16le = require('./lib/utf16le')

const LE = new Uint8Array(Uint16Array.of(0xff).buffer)[0] === 0xff

function codecFor (encoding) {
  switch (encoding) {
    case 'ascii':
      return ascii
    case 'base64':
      return base64
    case 'hex':
      return hex
    case 'utf8':
    case 'utf-8':
    case undefined:
      return utf8
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return utf16le
    default:
      throw new Error(`Unknown encoding: ${encoding}`)
  }
}

function isBuffer (value) {
  return value instanceof Uint8Array
}

function isEncoding (encoding) {
  try {
    codecFor(encoding)
    return true
  } catch {
    return false
  }
}

function alloc (size, fill, encoding) {
  const buffer = new Uint8Array(size)
  if (fill !== undefined) exports.fill(buffer, fill, 0, buffer.byteLength, encoding)
  return buffer
}

function allocUnsafe (size) {
  return new Uint8Array(size)
}

function allocUnsafeSlow (size) {
  return new Uint8Array(size)
}

function byteLength (string, encoding) {
  return codecFor(encoding).byteLength(string)
}

function compare (a, b) {
  if (a === b) return 0

  const len = Math.min(a.byteLength, b.byteLength)

  a = new DataView(a.buffer, a.byteOffset, a.byteLength)
  b = new DataView(b.buffer, b.byteOffset, b.byteLength)

  let i = 0

  for (let n = len - (len % 4); i < n; i += 4) {
    const x = a.getUint32(i, LE)
    const y = b.getUint32(i, LE)
    if (x !== y) break
  }

  for (; i < len; i++) {
    const x = a.getUint8(i)
    const y = b.getUint8(i)
    if (x < y) return -1
    if (x > y) return 1
  }

  return a.byteLength > b.byteLength ? 1 : a.byteLength < b.byteLength ? -1 : 0
}

function concat (buffers, totalLength) {
  if (totalLength === undefined) {
    totalLength = buffers.reduce((len, buffer) => len + buffer.byteLength, 0)
  }

  const result = new Uint8Array(totalLength)

  let offset = 0
  for (const buffer of buffers) {
    if (offset + buffer.byteLength > result.byteLength) {
      const sub = buffer.subarray(0, result.byteLength - offset)
      result.set(sub, offset)
      return result
    }
    result.set(buffer, offset)
    offset += buffer.byteLength
  }

  return result
}

function copy (source, target, targetStart = 0, start = 0, end = source.byteLength) {
  if (end > 0 && end < start) return 0
  if (end === start) return 0
  if (source.byteLength === 0 || target.byteLength === 0) return 0

  if (targetStart < 0) throw new RangeError('targetStart is out of range')
  if (start < 0 || start >= source.byteLength) throw new RangeError('sourceStart is out of range')
  if (end < 0) throw new RangeError('sourceEnd is out of range')

  if (targetStart >= target.byteLength) targetStart = target.byteLength
  if (end > source.byteLength) end = source.byteLength
  if (target.byteLength - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  const len = end - start

  if (source === target) {
    target.copyWithin(targetStart, start, end)
  } else {
    target.set(source.subarray(start, end), targetStart)
  }

  return len
}

function equals (a, b) {
  if (a === b) return true
  if (a.byteLength !== b.byteLength) return false

  const len = a.byteLength

  a = new DataView(a.buffer, a.byteOffset, a.byteLength)
  b = new DataView(b.buffer, b.byteOffset, b.byteLength)

  let i = 0

  for (let n = len - (len % 4); i < n; i += 4) {
    if (a.getUint32(i, LE) !== b.getUint32(i, LE)) return false
  }

  for (; i < len; i++) {
    if (a.getUint8(i) !== b.getUint8(i)) return false
  }

  return true
}

function fill (buffer, value, offset, end, encoding) {
  if (typeof value === 'string') {
    // fill(buffer, string, encoding)
    if (typeof offset === 'string') {
      encoding = offset
      offset = 0
      end = buffer.byteLength

    // fill(buffer, string, offset, encoding)
    } else if (typeof end === 'string') {
      encoding = end
      end = buffer.byteLength
    }
  } else if (typeof value === 'number') {
    value = value & 0xff
  } else if (typeof value === 'boolean') {
    value = +value
  }

  if (offset < 0 || buffer.byteLength < offset || buffer.byteLength < end) {
    throw new RangeError('Out of range index')
  }

  if (offset === undefined) offset = 0
  if (end === undefined) end = buffer.byteLength

  if (end <= offset) return buffer

  if (!value) value = 0

  if (typeof value === 'number') {
    for (let i = offset; i < end; ++i) {
      buffer[i] = value
    }
  } else {
    value = isBuffer(value) ? value : from(value, encoding)

    const len = value.byteLength

    for (let i = 0; i < end - offset; ++i) {
      buffer[i + offset] = value[i % len]
    }
  }

  return buffer
}

function from (value, encodingOrOffset, length) {
  // from(string, encoding)
  if (typeof value === 'string') return fromString(value, encodingOrOffset)

  // from(array)
  if (Array.isArray(value)) return fromArray(value)

  // from(buffer)
  if (ArrayBuffer.isView(value)) return fromBuffer(value)

  // from(arrayBuffer[, byteOffset[, length]])
  return fromArrayBuffer(value, encodingOrOffset, length)
}

function fromString (string, encoding) {
  const codec = codecFor(encoding)
  const buffer = new Uint8Array(codec.byteLength(string))
  codec.write(buffer, string, 0, buffer.byteLength)
  return buffer
}

function fromArray (array) {
  const buffer = new Uint8Array(array.length)
  buffer.set(array)
  return buffer
}

function fromBuffer (buffer) {
  const copy = new Uint8Array(buffer.byteLength)
  copy.set(buffer)
  return copy
}

function fromArrayBuffer (arrayBuffer, byteOffset, length) {
  return new Uint8Array(arrayBuffer, byteOffset, length)
}

function includes (buffer, value, byteOffset, encoding) {
  return indexOf(buffer, value, byteOffset, encoding) !== -1
}

function bidirectionalIndexOf (buffer, value, byteOffset, encoding, first) {
  if (buffer.byteLength === 0) return -1

  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset === undefined) {
    byteOffset = first ? 0 : (buffer.length - 1)
  } else if (byteOffset < 0) {
    byteOffset += buffer.byteLength
  }

  if (byteOffset >= buffer.byteLength) {
    if (first) return -1
    else byteOffset = buffer.byteLength - 1
  } else if (byteOffset < 0) {
    if (first) byteOffset = 0
    else return -1
  }

  if (typeof value === 'string') {
    value = from(value, encoding)
  } else if (typeof value === 'number') {
    value = value & 0xff

    if (first) {
      return buffer.indexOf(value, byteOffset)
    } else {
      return buffer.lastIndexOf(value, byteOffset)
    }
  }

  if (value.byteLength === 0) return -1

  if (first) {
    let foundIndex = -1

    for (let i = byteOffset; i < buffer.byteLength; i++) {
      if (buffer[i] === value[foundIndex === -1 ? 0 : i - foundIndex]) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === value.byteLength) return foundIndex
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + value.byteLength > buffer.byteLength) {
      byteOffset = buffer.byteLength - value.byteLength
    }

    for (let i = byteOffset; i >= 0; i--) {
      let found = true

      for (let j = 0; j < value.byteLength; j++) {
        if (buffer[i + j] !== value[j]) {
          found = false
          break
        }
      }

      if (found) return i
    }
  }

  return -1
}

function indexOf (buffer, value, byteOffset, encoding) {
  return bidirectionalIndexOf(buffer, value, byteOffset, encoding, true /* first */)
}

function lastIndexOf (buffer, value, byteOffset, encoding) {
  return bidirectionalIndexOf(buffer, value, byteOffset, encoding, false /* last */)
}

function swap (buffer, n, m) {
  const i = buffer[n]
  buffer[n] = buffer[m]
  buffer[m] = i
}

function swap16 (buffer) {
  const len = buffer.byteLength

  if (len % 2 !== 0) throw new RangeError('Buffer size must be a multiple of 16-bits')

  for (let i = 0; i < len; i += 2) swap(buffer, i, i + 1)

  return buffer
}

function swap32 (buffer) {
  const len = buffer.byteLength

  if (len % 4 !== 0) throw new RangeError('Buffer size must be a multiple of 32-bits')

  for (let i = 0; i < len; i += 4) {
    swap(buffer, i, i + 3)
    swap(buffer, i + 1, i + 2)
  }

  return buffer
}

function swap64 (buffer) {
  const len = buffer.byteLength

  if (len % 8 !== 0) throw new RangeError('Buffer size must be a multiple of 64-bits')

  for (let i = 0; i < len; i += 8) {
    swap(buffer, i, i + 7)
    swap(buffer, i + 1, i + 6)
    swap(buffer, i + 2, i + 5)
    swap(buffer, i + 3, i + 4)
  }

  return buffer
}

function toBuffer (buffer) {
  return buffer
}

function toString (buffer, encoding, start = 0, end = buffer.byteLength) {
  const len = buffer.byteLength

  if (start >= len) return ''
  if (end <= start) return ''
  if (start < 0) start = 0
  if (end > len) end = len

  if (start !== 0 || end < len) buffer = buffer.subarray(start, end)

  return codecFor(encoding).toString(buffer)
}

function write (buffer, string, offset, length, encoding) {
  // write(buffer, string)
  if (offset === undefined) {
    encoding = 'utf8'

  // write(buffer, string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    offset = undefined

  // write(buffer, string, offset, encoding)
  } else if (encoding === undefined && typeof length === 'string') {
    encoding = length
    length = undefined
  }

  return codecFor(encoding).write(buffer, string, offset, length)
}

function writeDoubleLE (buffer, value, offset) {
  if (offset === undefined) offset = 0

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  view.setFloat64(offset, value, true)

  return offset + 8
}

function writeFloatLE (buffer, value, offset) {
  if (offset === undefined) offset = 0

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  view.setFloat32(offset, value, true)

  return offset + 4
}

function writeUInt32LE (buffer, value, offset) {
  if (offset === undefined) offset = 0

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  view.setUint32(offset, value, true)

  return offset + 4
}

function writeInt32LE (buffer, value, offset) {
  if (offset === undefined) offset = 0

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  view.setInt32(offset, value, true)

  return offset + 4
}

function readDoubleLE (buffer, offset) {
  if (offset === undefined) offset = 0

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)

  return view.getFloat64(offset, true)
}

function readFloatLE (buffer, offset) {
  if (offset === undefined) offset = 0

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)

  return view.getFloat32(offset, true)
}

function readUInt32LE (buffer, offset) {
  if (offset === undefined) offset = 0

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)

  return view.getUint32(offset, true)
}

function readInt32LE (buffer, offset) {
  if (offset === undefined) offset = 0

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)

  return view.getInt32(offset, true)
}

module.exports = exports = {
  isBuffer,
  isEncoding,
  alloc,
  allocUnsafe,
  allocUnsafeSlow,
  byteLength,
  compare,
  concat,
  copy,
  equals,
  fill,
  from,
  includes,
  indexOf,
  lastIndexOf,
  swap16,
  swap32,
  swap64,
  toBuffer,
  toString,
  write,
  writeDoubleLE,
  writeFloatLE,
  writeUInt32LE,
  writeInt32LE,
  readDoubleLE,
  readFloatLE,
  readUInt32LE,
  readInt32LE
}

},{"./lib/ascii":5,"./lib/base64":6,"./lib/hex":7,"./lib/utf16le":8,"./lib/utf8":9}],5:[function(require,module,exports){
function byteLength (string) {
  return string.length
}

function toString (buffer) {
  const len = buffer.byteLength

  let result = ''

  for (let i = 0; i < len; i++) {
    result += String.fromCharCode(buffer[i])
  }

  return result
}

function write (buffer, string, offset = 0, length = byteLength(string)) {
  const len = Math.min(length, buffer.byteLength - offset)

  for (let i = 0; i < len; i++) {
    buffer[offset + i] = string.charCodeAt(i)
  }

  return len
}

module.exports = {
  byteLength,
  toString,
  write
}

},{}],6:[function(require,module,exports){
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

const codes = new Uint8Array(256)

for (let i = 0; i < alphabet.length; i++) {
  codes[alphabet.charCodeAt(i)] = i
}

codes[/* - */ 0x2d] = 62
codes[/* _ */ 0x5f] = 63

function byteLength (string) {
  let len = string.length

  if (string.charCodeAt(len - 1) === 0x3d) len--
  if (len > 1 && string.charCodeAt(len - 1) === 0x3d) len--

  return (len * 3) >>> 2
}

function toString (buffer) {
  const len = buffer.byteLength

  let result = ''

  for (let i = 0; i < len; i += 3) {
    result += (
      alphabet[buffer[i] >> 2] +
      alphabet[((buffer[i] & 3) << 4) | (buffer[i + 1] >> 4)] +
      alphabet[((buffer[i + 1] & 15) << 2) | (buffer[i + 2] >> 6)] +
      alphabet[buffer[i + 2] & 63]
    )
  }

  if (len % 3 === 2) {
    result = result.substring(0, result.length - 1) + '='
  } else if (len % 3 === 1) {
    result = result.substring(0, result.length - 2) + '=='
  }

  return result
};

function write (buffer, string, offset = 0, length = byteLength(string)) {
  const len = Math.min(length, buffer.byteLength - offset)

  for (let i = 0, j = 0; j < len; i += 4) {
    const a = codes[string.charCodeAt(i)]
    const b = codes[string.charCodeAt(i + 1)]
    const c = codes[string.charCodeAt(i + 2)]
    const d = codes[string.charCodeAt(i + 3)]

    buffer[j++] = (a << 2) | (b >> 4)
    buffer[j++] = ((b & 15) << 4) | (c >> 2)
    buffer[j++] = ((c & 3) << 6) | (d & 63)
  }

  return len
};

module.exports = {
  byteLength,
  toString,
  write
}

},{}],7:[function(require,module,exports){
function byteLength (string) {
  return string.length >>> 1
}

function toString (buffer) {
  const len = buffer.byteLength

  buffer = new DataView(buffer.buffer, buffer.byteOffset, len)

  let result = ''
  let i = 0

  for (let n = len - (len % 4); i < n; i += 4) {
    result += buffer.getUint32(i).toString(16).padStart(8, '0')
  }

  for (; i < len; i++) {
    result += buffer.getUint8(i).toString(16).padStart(2, '0')
  }

  return result
}

function write (buffer, string, offset = 0, length = byteLength(string)) {
  const len = Math.min(length, buffer.byteLength - offset)

  for (let i = 0; i < len; i++) {
    const a = hexValue(string.charCodeAt(i * 2))
    const b = hexValue(string.charCodeAt(i * 2 + 1))

    if (a === undefined || b === undefined) {
      return buffer.subarray(0, i)
    }

    buffer[offset + i] = (a << 4) | b
  }

  return len
}

module.exports = {
  byteLength,
  toString,
  write
}

function hexValue (char) {
  if (char >= 0x30 && char <= 0x39) return char - 0x30
  if (char >= 0x41 && char <= 0x46) return char - 0x41 + 10
  if (char >= 0x61 && char <= 0x66) return char - 0x61 + 10
}

},{}],8:[function(require,module,exports){
function byteLength (string) {
  return string.length * 2
}

function toString (buffer) {
  const len = buffer.byteLength

  let result = ''

  for (let i = 0; i < len - 1; i += 2) {
    result += String.fromCharCode(buffer[i] + (buffer[i + 1] * 256))
  }

  return result
}

function write (buffer, string, offset = 0, length = byteLength(string)) {
  const len = Math.min(length, buffer.byteLength - offset)

  let units = len

  for (let i = 0; i < string.length; ++i) {
    if ((units -= 2) < 0) break

    const c = string.charCodeAt(i)
    const hi = c >> 8
    const lo = c % 256

    buffer[offset + i * 2] = lo
    buffer[offset + i * 2 + 1] = hi
  }

  return len
}

module.exports = {
  byteLength,
  toString,
  write
}

},{}],9:[function(require,module,exports){
function byteLength (string) {
  let length = 0

  for (let i = 0, n = string.length; i < n; i++) {
    const code = string.charCodeAt(i)

    if (code >= 0xd800 && code <= 0xdbff && i + 1 < n) {
      const code = string.charCodeAt(i + 1)

      if (code >= 0xdc00 && code <= 0xdfff) {
        length += 4
        i++
        continue
      }
    }

    if (code <= 0x7f) length += 1
    else if (code <= 0x7ff) length += 2
    else length += 3
  }

  return length
}

let toString

if (typeof TextDecoder !== 'undefined') {
  const decoder = new TextDecoder()

  toString = function toString (buffer) {
    return decoder.decode(buffer)
  }
} else {
  toString = function toString (buffer) {
    const len = buffer.byteLength

    let output = ''
    let i = 0

    while (i < len) {
      let byte = buffer[i]

      if (byte <= 0x7f) {
        output += String.fromCharCode(byte)
        i++
        continue
      }

      let bytesNeeded = 0
      let codePoint = 0

      if (byte <= 0xdf) {
        bytesNeeded = 1
        codePoint = byte & 0x1f
      } else if (byte <= 0xef) {
        bytesNeeded = 2
        codePoint = byte & 0x0f
      } else if (byte <= 0xf4) {
        bytesNeeded = 3
        codePoint = byte & 0x07
      }

      if (len - i - bytesNeeded > 0) {
        let k = 0

        while (k < bytesNeeded) {
          byte = buffer[i + k + 1]
          codePoint = (codePoint << 6) | (byte & 0x3f)
          k += 1
        }
      } else {
        codePoint = 0xfffd
        bytesNeeded = len - i
      }

      output += String.fromCodePoint(codePoint)
      i += bytesNeeded + 1
    }

    return output
  }
}

let write

if (typeof TextEncoder !== 'undefined') {
  const encoder = new TextEncoder()

  write = function write (buffer, string, offset = 0, length = byteLength(string)) {
    const len = Math.min(length, buffer.byteLength - offset)
    encoder.encodeInto(string, buffer.subarray(offset, offset + len))
    return len
  }
} else {
  write = function write (buffer, string, offset = 0, length = byteLength(string)) {
    const len = Math.min(length, buffer.byteLength - offset)

    buffer = buffer.subarray(offset, offset + len)

    let i = 0
    let j = 0

    while (i < string.length) {
      const code = string.codePointAt(i)

      if (code <= 0x7f) {
        buffer[j++] = code
        i++
        continue
      }

      let count = 0
      let bits = 0

      if (code <= 0x7ff) {
        count = 6
        bits = 0xc0
      } else if (code <= 0xffff) {
        count = 12
        bits = 0xe0
      } else if (code <= 0x1fffff) {
        count = 18
        bits = 0xf0
      }

      buffer[j++] = bits | (code >> count)
      count -= 6

      while (count >= 0) {
        buffer[j++] = 0x80 | ((code >> count) & 0x3f)
        count -= 6
      }

      i += code >= 0x10000 ? 2 : 1
    }

    return len
  }
}

module.exports = {
  byteLength,
  toString,
  write
}

},{}],10:[function(require,module,exports){
const FACTOR = new Uint16Array(8)

function factor4096 (i, n) {
  while (n > 0) {
    const f = i & 4095
    FACTOR[--n] = f
    i = (i - f) / 4096
  }
  return FACTOR
}

module.exports = class BigSparseArray {
  constructor () {
    this.tiny = new TinyArray()
    this.maxLength = 4096
    this.factor = 1
  }

  set (index, val) {
    if (val !== undefined) {
      while (index >= this.maxLength) {
        this.maxLength *= 4096
        this.factor++
        if (!this.tiny.isEmptyish()) {
          const t = new TinyArray()
          t.set(0, this.tiny)
          this.tiny = t
        }
      }
    }

    const f = factor4096(index, this.factor)
    const last = this.factor - 1

    let tiny = this.tiny
    for (let i = 0; i < last; i++) {
      const next = tiny.get(f[i])
      if (next === undefined) {
        if (val === undefined) return
        tiny = tiny.set(f[i], new TinyArray())
      } else {
        tiny = next
      }
    }

    return tiny.set(f[last], val)
  }

  get (index) {
    if (index >= this.maxLength) return

    const f = factor4096(index, this.factor)
    const last = this.factor - 1

    let tiny = this.tiny
    for (let i = 0; i < last; i++) {
      tiny = tiny.get(f[i])
      if (tiny === undefined) return
    }

    return tiny.get(f[last])
  }
}

class TinyArray {
  constructor () {
    this.s = 0
    this.b = new Array(1)
    this.f = new Uint16Array(1)
  }

  isEmptyish () {
    return this.b.length === 1 && this.b[0] === undefined
  }

  get (i) {
    if (this.s === 12) return this.b[i]
    const f = i >>> this.s
    const r = i & (this.b.length - 1)
    return this.f[r] === f ? this.b[r] : undefined
  }

  set (i, v) {
    while (this.s !== 12) {
      const f = i >>> this.s
      const r = i & (this.b.length - 1)
      const o = this.b[r]

      if (o === undefined || f === this.f[r]) {
        this.b[r] = v
        this.f[r] = f
        return v
      }

      this.grow()
    }

    this.b[i] = v
    return v
  }

  grow () {
    const os = this.s
    const ob = this.b
    const of = this.f

    this.s += 4
    this.b = new Array(this.b.length << 4)
    this.f = this.s === 12 ? null : new Uint8Array(this.b.length)

    const m = this.b.length - 1

    for (let or = 0; or < ob.length; or++) {
      if (ob[or] === undefined) continue

      const i = of[or] << os | or
      const f = i >>> this.s
      const r = i & m

      this.b[r] = ob[or]
      if (this.s !== 12) this.f[r] = f
    }
  }
}

},{}],11:[function(require,module,exports){
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[Object.keys(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __toBinary = /* @__PURE__ */ (() => {
  var table = new Uint8Array(128);
  for (var i = 0; i < 64; i++)
    table[i < 26 ? i + 65 : i < 52 ? i + 71 : i < 62 ? i - 4 : i * 4 - 205] = i;
  return (base64) => {
    var n = base64.length, bytes2 = new Uint8Array((n - (base64[n - 1] == "=") - (base64[n - 2] == "=")) * 3 / 4 | 0);
    for (var i2 = 0, j = 0; i2 < n; ) {
      var c0 = table[base64.charCodeAt(i2++)], c1 = table[base64.charCodeAt(i2++)];
      var c2 = table[base64.charCodeAt(i2++)], c3 = table[base64.charCodeAt(i2++)];
      bytes2[j++] = c0 << 2 | c1 >> 4;
      bytes2[j++] = c1 << 4 | c2 >> 2;
      bytes2[j++] = c2 << 6 | c3;
    }
    return bytes2;
  };
})();

// wasm-binary:./blake2b.wat
var require_blake2b = __commonJS({
  "wasm-binary:./blake2b.wat"(exports2, module2) {
    module2.exports = __toBinary("AGFzbQEAAAABEANgAn9/AGADf39/AGABfwADBQQAAQICBQUBAQroBwdNBQZtZW1vcnkCAAxibGFrZTJiX2luaXQAAA5ibGFrZTJiX3VwZGF0ZQABDWJsYWtlMmJfZmluYWwAAhBibGFrZTJiX2NvbXByZXNzAAMKvz8EwAIAIABCADcDACAAQgA3AwggAEIANwMQIABCADcDGCAAQgA3AyAgAEIANwMoIABCADcDMCAAQgA3AzggAEIANwNAIABCADcDSCAAQgA3A1AgAEIANwNYIABCADcDYCAAQgA3A2ggAEIANwNwIABCADcDeCAAQoiS853/zPmE6gBBACkDAIU3A4ABIABCu86qptjQ67O7f0EIKQMAhTcDiAEgAEKr8NP0r+68tzxBECkDAIU3A5ABIABC8e30+KWn/aelf0EYKQMAhTcDmAEgAELRhZrv+s+Uh9EAQSApAwCFNwOgASAAQp/Y+dnCkdqCm39BKCkDAIU3A6gBIABC6/qG2r+19sEfQTApAwCFNwOwASAAQvnC+JuRo7Pw2wBBOCkDAIU3A7gBIABCADcDwAEgAEIANwPIASAAQgA3A9ABC20BA38gAEHAAWohAyAAQcgBaiEEIAQpAwCnIQUCQANAIAEgAkYNASAFQYABRgRAIAMgAykDACAFrXw3AwBBACEFIAAQAwsgACAFaiABLQAAOgAAIAVBAWohBSABQQFqIQEMAAsLIAQgBa03AwALYQEDfyAAQcABaiEBIABByAFqIQIgASABKQMAIAIpAwB8NwMAIABCfzcD0AEgAikDAKchAwJAA0AgA0GAAUYNASAAIANqQQA6AAAgA0EBaiEDDAALCyACIAOtNwMAIAAQAwuqOwIgfgl/IABBgAFqISEgAEGIAWohIiAAQZABaiEjIABBmAFqISQgAEGgAWohJSAAQagBaiEmIABBsAFqIScgAEG4AWohKCAhKQMAIQEgIikDACECICMpAwAhAyAkKQMAIQQgJSkDACEFICYpAwAhBiAnKQMAIQcgKCkDACEIQoiS853/zPmE6gAhCUK7zqqm2NDrs7t/IQpCq/DT9K/uvLc8IQtC8e30+KWn/aelfyEMQtGFmu/6z5SH0QAhDUKf2PnZwpHagpt/IQ5C6/qG2r+19sEfIQ9C+cL4m5Gjs/DbACEQIAApAwAhESAAKQMIIRIgACkDECETIAApAxghFCAAKQMgIRUgACkDKCEWIAApAzAhFyAAKQM4IRggACkDQCEZIAApA0ghGiAAKQNQIRsgACkDWCEcIAApA2AhHSAAKQNoIR4gACkDcCEfIAApA3ghICANIAApA8ABhSENIA8gACkD0AGFIQ8gASAFIBF8fCEBIA0gAYVCIIohDSAJIA18IQkgBSAJhUIYiiEFIAEgBSASfHwhASANIAGFQhCKIQ0gCSANfCEJIAUgCYVCP4ohBSACIAYgE3x8IQIgDiAChUIgiiEOIAogDnwhCiAGIAqFQhiKIQYgAiAGIBR8fCECIA4gAoVCEIohDiAKIA58IQogBiAKhUI/iiEGIAMgByAVfHwhAyAPIAOFQiCKIQ8gCyAPfCELIAcgC4VCGIohByADIAcgFnx8IQMgDyADhUIQiiEPIAsgD3whCyAHIAuFQj+KIQcgBCAIIBd8fCEEIBAgBIVCIIohECAMIBB8IQwgCCAMhUIYiiEIIAQgCCAYfHwhBCAQIASFQhCKIRAgDCAQfCEMIAggDIVCP4ohCCABIAYgGXx8IQEgECABhUIgiiEQIAsgEHwhCyAGIAuFQhiKIQYgASAGIBp8fCEBIBAgAYVCEIohECALIBB8IQsgBiALhUI/iiEGIAIgByAbfHwhAiANIAKFQiCKIQ0gDCANfCEMIAcgDIVCGIohByACIAcgHHx8IQIgDSAChUIQiiENIAwgDXwhDCAHIAyFQj+KIQcgAyAIIB18fCEDIA4gA4VCIIohDiAJIA58IQkgCCAJhUIYiiEIIAMgCCAefHwhAyAOIAOFQhCKIQ4gCSAOfCEJIAggCYVCP4ohCCAEIAUgH3x8IQQgDyAEhUIgiiEPIAogD3whCiAFIAqFQhiKIQUgBCAFICB8fCEEIA8gBIVCEIohDyAKIA98IQogBSAKhUI/iiEFIAEgBSAffHwhASANIAGFQiCKIQ0gCSANfCEJIAUgCYVCGIohBSABIAUgG3x8IQEgDSABhUIQiiENIAkgDXwhCSAFIAmFQj+KIQUgAiAGIBV8fCECIA4gAoVCIIohDiAKIA58IQogBiAKhUIYiiEGIAIgBiAZfHwhAiAOIAKFQhCKIQ4gCiAOfCEKIAYgCoVCP4ohBiADIAcgGnx8IQMgDyADhUIgiiEPIAsgD3whCyAHIAuFQhiKIQcgAyAHICB8fCEDIA8gA4VCEIohDyALIA98IQsgByALhUI/iiEHIAQgCCAefHwhBCAQIASFQiCKIRAgDCAQfCEMIAggDIVCGIohCCAEIAggF3x8IQQgECAEhUIQiiEQIAwgEHwhDCAIIAyFQj+KIQggASAGIBJ8fCEBIBAgAYVCIIohECALIBB8IQsgBiALhUIYiiEGIAEgBiAdfHwhASAQIAGFQhCKIRAgCyAQfCELIAYgC4VCP4ohBiACIAcgEXx8IQIgDSAChUIgiiENIAwgDXwhDCAHIAyFQhiKIQcgAiAHIBN8fCECIA0gAoVCEIohDSAMIA18IQwgByAMhUI/iiEHIAMgCCAcfHwhAyAOIAOFQiCKIQ4gCSAOfCEJIAggCYVCGIohCCADIAggGHx8IQMgDiADhUIQiiEOIAkgDnwhCSAIIAmFQj+KIQggBCAFIBZ8fCEEIA8gBIVCIIohDyAKIA98IQogBSAKhUIYiiEFIAQgBSAUfHwhBCAPIASFQhCKIQ8gCiAPfCEKIAUgCoVCP4ohBSABIAUgHHx8IQEgDSABhUIgiiENIAkgDXwhCSAFIAmFQhiKIQUgASAFIBl8fCEBIA0gAYVCEIohDSAJIA18IQkgBSAJhUI/iiEFIAIgBiAdfHwhAiAOIAKFQiCKIQ4gCiAOfCEKIAYgCoVCGIohBiACIAYgEXx8IQIgDiAChUIQiiEOIAogDnwhCiAGIAqFQj+KIQYgAyAHIBZ8fCEDIA8gA4VCIIohDyALIA98IQsgByALhUIYiiEHIAMgByATfHwhAyAPIAOFQhCKIQ8gCyAPfCELIAcgC4VCP4ohByAEIAggIHx8IQQgECAEhUIgiiEQIAwgEHwhDCAIIAyFQhiKIQggBCAIIB58fCEEIBAgBIVCEIohECAMIBB8IQwgCCAMhUI/iiEIIAEgBiAbfHwhASAQIAGFQiCKIRAgCyAQfCELIAYgC4VCGIohBiABIAYgH3x8IQEgECABhUIQiiEQIAsgEHwhCyAGIAuFQj+KIQYgAiAHIBR8fCECIA0gAoVCIIohDSAMIA18IQwgByAMhUIYiiEHIAIgByAXfHwhAiANIAKFQhCKIQ0gDCANfCEMIAcgDIVCP4ohByADIAggGHx8IQMgDiADhUIgiiEOIAkgDnwhCSAIIAmFQhiKIQggAyAIIBJ8fCEDIA4gA4VCEIohDiAJIA58IQkgCCAJhUI/iiEIIAQgBSAafHwhBCAPIASFQiCKIQ8gCiAPfCEKIAUgCoVCGIohBSAEIAUgFXx8IQQgDyAEhUIQiiEPIAogD3whCiAFIAqFQj+KIQUgASAFIBh8fCEBIA0gAYVCIIohDSAJIA18IQkgBSAJhUIYiiEFIAEgBSAafHwhASANIAGFQhCKIQ0gCSANfCEJIAUgCYVCP4ohBSACIAYgFHx8IQIgDiAChUIgiiEOIAogDnwhCiAGIAqFQhiKIQYgAiAGIBJ8fCECIA4gAoVCEIohDiAKIA58IQogBiAKhUI/iiEGIAMgByAefHwhAyAPIAOFQiCKIQ8gCyAPfCELIAcgC4VCGIohByADIAcgHXx8IQMgDyADhUIQiiEPIAsgD3whCyAHIAuFQj+KIQcgBCAIIBx8fCEEIBAgBIVCIIohECAMIBB8IQwgCCAMhUIYiiEIIAQgCCAffHwhBCAQIASFQhCKIRAgDCAQfCEMIAggDIVCP4ohCCABIAYgE3x8IQEgECABhUIgiiEQIAsgEHwhCyAGIAuFQhiKIQYgASAGIBd8fCEBIBAgAYVCEIohECALIBB8IQsgBiALhUI/iiEGIAIgByAWfHwhAiANIAKFQiCKIQ0gDCANfCEMIAcgDIVCGIohByACIAcgG3x8IQIgDSAChUIQiiENIAwgDXwhDCAHIAyFQj+KIQcgAyAIIBV8fCEDIA4gA4VCIIohDiAJIA58IQkgCCAJhUIYiiEIIAMgCCARfHwhAyAOIAOFQhCKIQ4gCSAOfCEJIAggCYVCP4ohCCAEIAUgIHx8IQQgDyAEhUIgiiEPIAogD3whCiAFIAqFQhiKIQUgBCAFIBl8fCEEIA8gBIVCEIohDyAKIA98IQogBSAKhUI/iiEFIAEgBSAafHwhASANIAGFQiCKIQ0gCSANfCEJIAUgCYVCGIohBSABIAUgEXx8IQEgDSABhUIQiiENIAkgDXwhCSAFIAmFQj+KIQUgAiAGIBZ8fCECIA4gAoVCIIohDiAKIA58IQogBiAKhUIYiiEGIAIgBiAYfHwhAiAOIAKFQhCKIQ4gCiAOfCEKIAYgCoVCP4ohBiADIAcgE3x8IQMgDyADhUIgiiEPIAsgD3whCyAHIAuFQhiKIQcgAyAHIBV8fCEDIA8gA4VCEIohDyALIA98IQsgByALhUI/iiEHIAQgCCAbfHwhBCAQIASFQiCKIRAgDCAQfCEMIAggDIVCGIohCCAEIAggIHx8IQQgECAEhUIQiiEQIAwgEHwhDCAIIAyFQj+KIQggASAGIB98fCEBIBAgAYVCIIohECALIBB8IQsgBiALhUIYiiEGIAEgBiASfHwhASAQIAGFQhCKIRAgCyAQfCELIAYgC4VCP4ohBiACIAcgHHx8IQIgDSAChUIgiiENIAwgDXwhDCAHIAyFQhiKIQcgAiAHIB18fCECIA0gAoVCEIohDSAMIA18IQwgByAMhUI/iiEHIAMgCCAXfHwhAyAOIAOFQiCKIQ4gCSAOfCEJIAggCYVCGIohCCADIAggGXx8IQMgDiADhUIQiiEOIAkgDnwhCSAIIAmFQj+KIQggBCAFIBR8fCEEIA8gBIVCIIohDyAKIA98IQogBSAKhUIYiiEFIAQgBSAefHwhBCAPIASFQhCKIQ8gCiAPfCEKIAUgCoVCP4ohBSABIAUgE3x8IQEgDSABhUIgiiENIAkgDXwhCSAFIAmFQhiKIQUgASAFIB18fCEBIA0gAYVCEIohDSAJIA18IQkgBSAJhUI/iiEFIAIgBiAXfHwhAiAOIAKFQiCKIQ4gCiAOfCEKIAYgCoVCGIohBiACIAYgG3x8IQIgDiAChUIQiiEOIAogDnwhCiAGIAqFQj+KIQYgAyAHIBF8fCEDIA8gA4VCIIohDyALIA98IQsgByALhUIYiiEHIAMgByAcfHwhAyAPIAOFQhCKIQ8gCyAPfCELIAcgC4VCP4ohByAEIAggGXx8IQQgECAEhUIgiiEQIAwgEHwhDCAIIAyFQhiKIQggBCAIIBR8fCEEIBAgBIVCEIohECAMIBB8IQwgCCAMhUI/iiEIIAEgBiAVfHwhASAQIAGFQiCKIRAgCyAQfCELIAYgC4VCGIohBiABIAYgHnx8IQEgECABhUIQiiEQIAsgEHwhCyAGIAuFQj+KIQYgAiAHIBh8fCECIA0gAoVCIIohDSAMIA18IQwgByAMhUIYiiEHIAIgByAWfHwhAiANIAKFQhCKIQ0gDCANfCEMIAcgDIVCP4ohByADIAggIHx8IQMgDiADhUIgiiEOIAkgDnwhCSAIIAmFQhiKIQggAyAIIB98fCEDIA4gA4VCEIohDiAJIA58IQkgCCAJhUI/iiEIIAQgBSASfHwhBCAPIASFQiCKIQ8gCiAPfCEKIAUgCoVCGIohBSAEIAUgGnx8IQQgDyAEhUIQiiEPIAogD3whCiAFIAqFQj+KIQUgASAFIB18fCEBIA0gAYVCIIohDSAJIA18IQkgBSAJhUIYiiEFIAEgBSAWfHwhASANIAGFQhCKIQ0gCSANfCEJIAUgCYVCP4ohBSACIAYgEnx8IQIgDiAChUIgiiEOIAogDnwhCiAGIAqFQhiKIQYgAiAGICB8fCECIA4gAoVCEIohDiAKIA58IQogBiAKhUI/iiEGIAMgByAffHwhAyAPIAOFQiCKIQ8gCyAPfCELIAcgC4VCGIohByADIAcgHnx8IQMgDyADhUIQiiEPIAsgD3whCyAHIAuFQj+KIQcgBCAIIBV8fCEEIBAgBIVCIIohECAMIBB8IQwgCCAMhUIYiiEIIAQgCCAbfHwhBCAQIASFQhCKIRAgDCAQfCEMIAggDIVCP4ohCCABIAYgEXx8IQEgECABhUIgiiEQIAsgEHwhCyAGIAuFQhiKIQYgASAGIBh8fCEBIBAgAYVCEIohECALIBB8IQsgBiALhUI/iiEGIAIgByAXfHwhAiANIAKFQiCKIQ0gDCANfCEMIAcgDIVCGIohByACIAcgFHx8IQIgDSAChUIQiiENIAwgDXwhDCAHIAyFQj+KIQcgAyAIIBp8fCEDIA4gA4VCIIohDiAJIA58IQkgCCAJhUIYiiEIIAMgCCATfHwhAyAOIAOFQhCKIQ4gCSAOfCEJIAggCYVCP4ohCCAEIAUgGXx8IQQgDyAEhUIgiiEPIAogD3whCiAFIAqFQhiKIQUgBCAFIBx8fCEEIA8gBIVCEIohDyAKIA98IQogBSAKhUI/iiEFIAEgBSAefHwhASANIAGFQiCKIQ0gCSANfCEJIAUgCYVCGIohBSABIAUgHHx8IQEgDSABhUIQiiENIAkgDXwhCSAFIAmFQj+KIQUgAiAGIBh8fCECIA4gAoVCIIohDiAKIA58IQogBiAKhUIYiiEGIAIgBiAffHwhAiAOIAKFQhCKIQ4gCiAOfCEKIAYgCoVCP4ohBiADIAcgHXx8IQMgDyADhUIgiiEPIAsgD3whCyAHIAuFQhiKIQcgAyAHIBJ8fCEDIA8gA4VCEIohDyALIA98IQsgByALhUI/iiEHIAQgCCAUfHwhBCAQIASFQiCKIRAgDCAQfCEMIAggDIVCGIohCCAEIAggGnx8IQQgECAEhUIQiiEQIAwgEHwhDCAIIAyFQj+KIQggASAGIBZ8fCEBIBAgAYVCIIohECALIBB8IQsgBiALhUIYiiEGIAEgBiARfHwhASAQIAGFQhCKIRAgCyAQfCELIAYgC4VCP4ohBiACIAcgIHx8IQIgDSAChUIgiiENIAwgDXwhDCAHIAyFQhiKIQcgAiAHIBV8fCECIA0gAoVCEIohDSAMIA18IQwgByAMhUI/iiEHIAMgCCAZfHwhAyAOIAOFQiCKIQ4gCSAOfCEJIAggCYVCGIohCCADIAggF3x8IQMgDiADhUIQiiEOIAkgDnwhCSAIIAmFQj+KIQggBCAFIBN8fCEEIA8gBIVCIIohDyAKIA98IQogBSAKhUIYiiEFIAQgBSAbfHwhBCAPIASFQhCKIQ8gCiAPfCEKIAUgCoVCP4ohBSABIAUgF3x8IQEgDSABhUIgiiENIAkgDXwhCSAFIAmFQhiKIQUgASAFICB8fCEBIA0gAYVCEIohDSAJIA18IQkgBSAJhUI/iiEFIAIgBiAffHwhAiAOIAKFQiCKIQ4gCiAOfCEKIAYgCoVCGIohBiACIAYgGnx8IQIgDiAChUIQiiEOIAogDnwhCiAGIAqFQj+KIQYgAyAHIBx8fCEDIA8gA4VCIIohDyALIA98IQsgByALhUIYiiEHIAMgByAUfHwhAyAPIAOFQhCKIQ8gCyAPfCELIAcgC4VCP4ohByAEIAggEXx8IQQgECAEhUIgiiEQIAwgEHwhDCAIIAyFQhiKIQggBCAIIBl8fCEEIBAgBIVCEIohECAMIBB8IQwgCCAMhUI/iiEIIAEgBiAdfHwhASAQIAGFQiCKIRAgCyAQfCELIAYgC4VCGIohBiABIAYgE3x8IQEgECABhUIQiiEQIAsgEHwhCyAGIAuFQj+KIQYgAiAHIB58fCECIA0gAoVCIIohDSAMIA18IQwgByAMhUIYiiEHIAIgByAYfHwhAiANIAKFQhCKIQ0gDCANfCEMIAcgDIVCP4ohByADIAggEnx8IQMgDiADhUIgiiEOIAkgDnwhCSAIIAmFQhiKIQggAyAIIBV8fCEDIA4gA4VCEIohDiAJIA58IQkgCCAJhUI/iiEIIAQgBSAbfHwhBCAPIASFQiCKIQ8gCiAPfCEKIAUgCoVCGIohBSAEIAUgFnx8IQQgDyAEhUIQiiEPIAogD3whCiAFIAqFQj+KIQUgASAFIBt8fCEBIA0gAYVCIIohDSAJIA18IQkgBSAJhUIYiiEFIAEgBSATfHwhASANIAGFQhCKIQ0gCSANfCEJIAUgCYVCP4ohBSACIAYgGXx8IQIgDiAChUIgiiEOIAogDnwhCiAGIAqFQhiKIQYgAiAGIBV8fCECIA4gAoVCEIohDiAKIA58IQogBiAKhUI/iiEGIAMgByAYfHwhAyAPIAOFQiCKIQ8gCyAPfCELIAcgC4VCGIohByADIAcgF3x8IQMgDyADhUIQiiEPIAsgD3whCyAHIAuFQj+KIQcgBCAIIBJ8fCEEIBAgBIVCIIohECAMIBB8IQwgCCAMhUIYiiEIIAQgCCAWfHwhBCAQIASFQhCKIRAgDCAQfCEMIAggDIVCP4ohCCABIAYgIHx8IQEgECABhUIgiiEQIAsgEHwhCyAGIAuFQhiKIQYgASAGIBx8fCEBIBAgAYVCEIohECALIBB8IQsgBiALhUI/iiEGIAIgByAafHwhAiANIAKFQiCKIQ0gDCANfCEMIAcgDIVCGIohByACIAcgH3x8IQIgDSAChUIQiiENIAwgDXwhDCAHIAyFQj+KIQcgAyAIIBR8fCEDIA4gA4VCIIohDiAJIA58IQkgCCAJhUIYiiEIIAMgCCAdfHwhAyAOIAOFQhCKIQ4gCSAOfCEJIAggCYVCP4ohCCAEIAUgHnx8IQQgDyAEhUIgiiEPIAogD3whCiAFIAqFQhiKIQUgBCAFIBF8fCEEIA8gBIVCEIohDyAKIA98IQogBSAKhUI/iiEFIAEgBSARfHwhASANIAGFQiCKIQ0gCSANfCEJIAUgCYVCGIohBSABIAUgEnx8IQEgDSABhUIQiiENIAkgDXwhCSAFIAmFQj+KIQUgAiAGIBN8fCECIA4gAoVCIIohDiAKIA58IQogBiAKhUIYiiEGIAIgBiAUfHwhAiAOIAKFQhCKIQ4gCiAOfCEKIAYgCoVCP4ohBiADIAcgFXx8IQMgDyADhUIgiiEPIAsgD3whCyAHIAuFQhiKIQcgAyAHIBZ8fCEDIA8gA4VCEIohDyALIA98IQsgByALhUI/iiEHIAQgCCAXfHwhBCAQIASFQiCKIRAgDCAQfCEMIAggDIVCGIohCCAEIAggGHx8IQQgECAEhUIQiiEQIAwgEHwhDCAIIAyFQj+KIQggASAGIBl8fCEBIBAgAYVCIIohECALIBB8IQsgBiALhUIYiiEGIAEgBiAafHwhASAQIAGFQhCKIRAgCyAQfCELIAYgC4VCP4ohBiACIAcgG3x8IQIgDSAChUIgiiENIAwgDXwhDCAHIAyFQhiKIQcgAiAHIBx8fCECIA0gAoVCEIohDSAMIA18IQwgByAMhUI/iiEHIAMgCCAdfHwhAyAOIAOFQiCKIQ4gCSAOfCEJIAggCYVCGIohCCADIAggHnx8IQMgDiADhUIQiiEOIAkgDnwhCSAIIAmFQj+KIQggBCAFIB98fCEEIA8gBIVCIIohDyAKIA98IQogBSAKhUIYiiEFIAQgBSAgfHwhBCAPIASFQhCKIQ8gCiAPfCEKIAUgCoVCP4ohBSABIAUgH3x8IQEgDSABhUIgiiENIAkgDXwhCSAFIAmFQhiKIQUgASAFIBt8fCEBIA0gAYVCEIohDSAJIA18IQkgBSAJhUI/iiEFIAIgBiAVfHwhAiAOIAKFQiCKIQ4gCiAOfCEKIAYgCoVCGIohBiACIAYgGXx8IQIgDiAChUIQiiEOIAogDnwhCiAGIAqFQj+KIQYgAyAHIBp8fCEDIA8gA4VCIIohDyALIA98IQsgByALhUIYiiEHIAMgByAgfHwhAyAPIAOFQhCKIQ8gCyAPfCELIAcgC4VCP4ohByAEIAggHnx8IQQgECAEhUIgiiEQIAwgEHwhDCAIIAyFQhiKIQggBCAIIBd8fCEEIBAgBIVCEIohECAMIBB8IQwgCCAMhUI/iiEIIAEgBiASfHwhASAQIAGFQiCKIRAgCyAQfCELIAYgC4VCGIohBiABIAYgHXx8IQEgECABhUIQiiEQIAsgEHwhCyAGIAuFQj+KIQYgAiAHIBF8fCECIA0gAoVCIIohDSAMIA18IQwgByAMhUIYiiEHIAIgByATfHwhAiANIAKFQhCKIQ0gDCANfCEMIAcgDIVCP4ohByADIAggHHx8IQMgDiADhUIgiiEOIAkgDnwhCSAIIAmFQhiKIQggAyAIIBh8fCEDIA4gA4VCEIohDiAJIA58IQkgCCAJhUI/iiEIIAQgBSAWfHwhBCAPIASFQiCKIQ8gCiAPfCEKIAUgCoVCGIohBSAEIAUgFHx8IQQgDyAEhUIQiiEPIAogD3whCiAFIAqFQj+KIQUgISAhKQMAIAEgCYWFNwMAICIgIikDACACIAqFhTcDACAjICMpAwAgAyALhYU3AwAgJCAkKQMAIAQgDIWFNwMAICUgJSkDACAFIA2FhTcDACAmICYpAwAgBiAOhYU3AwAgJyAnKQMAIAcgD4WFNwMAICggKCkDACAIIBCFhTcDAAs=");
  }
});

// wasm-module:./blake2b.wat
var bytes = require_blake2b();
var compiled = WebAssembly.compile(bytes);
module.exports = async (imports) => {
  const instance = await WebAssembly.instantiate(await compiled, imports);
  return instance.exports;
};

},{}],12:[function(require,module,exports){
var assert = require('nanoassert')
var b4a = require('b4a')

var wasm = null
var wasmPromise = typeof WebAssembly !== "undefined" && require('./blake2b')().then(mod => {
  wasm = mod
})

var head = 64
var freeList = []

module.exports = Blake2b
var BYTES_MIN = module.exports.BYTES_MIN = 16
var BYTES_MAX = module.exports.BYTES_MAX = 64
var BYTES = module.exports.BYTES = 32
var KEYBYTES_MIN = module.exports.KEYBYTES_MIN = 16
var KEYBYTES_MAX = module.exports.KEYBYTES_MAX = 64
var KEYBYTES = module.exports.KEYBYTES = 32
var SALTBYTES = module.exports.SALTBYTES = 16
var PERSONALBYTES = module.exports.PERSONALBYTES = 16

function Blake2b (digestLength, key, salt, personal, noAssert) {
  if (!(this instanceof Blake2b)) return new Blake2b(digestLength, key, salt, personal, noAssert)
  if (!wasm) throw new Error('WASM not loaded. Wait for Blake2b.ready(cb)')
  if (!digestLength) digestLength = 32

  if (noAssert !== true) {
    assert(digestLength >= BYTES_MIN, 'digestLength must be at least ' + BYTES_MIN + ', was given ' + digestLength)
    assert(digestLength <= BYTES_MAX, 'digestLength must be at most ' + BYTES_MAX + ', was given ' + digestLength)
    if (key != null) {
      assert(key instanceof Uint8Array, 'key must be Uint8Array or Buffer')
      assert(key.length >= KEYBYTES_MIN, 'key must be at least ' + KEYBYTES_MIN + ', was given ' + key.length)
      assert(key.length <= KEYBYTES_MAX, 'key must be at least ' + KEYBYTES_MAX + ', was given ' + key.length)
    }
    if (salt != null) {
      assert(salt instanceof Uint8Array, 'salt must be Uint8Array or Buffer')
      assert(salt.length === SALTBYTES, 'salt must be exactly ' + SALTBYTES + ', was given ' + salt.length)
    }
    if (personal != null) {
      assert(personal instanceof Uint8Array, 'personal must be Uint8Array or Buffer')
      assert(personal.length === PERSONALBYTES, 'personal must be exactly ' + PERSONALBYTES + ', was given ' + personal.length)
    }
  }

  if (!freeList.length) {
    freeList.push(head)
    head += 216
  }

  this.digestLength = digestLength
  this.finalized = false
  this.pointer = freeList.pop()
  this._memory = new Uint8Array(wasm.memory.buffer)

  this._memory.fill(0, 0, 64)
  this._memory[0] = this.digestLength
  this._memory[1] = key ? key.length : 0
  this._memory[2] = 1 // fanout
  this._memory[3] = 1 // depth

  if (salt) this._memory.set(salt, 32)
  if (personal) this._memory.set(personal, 48)

  if (this.pointer + 216 > this._memory.length) this._realloc(this.pointer + 216) // we need 216 bytes for the state
  wasm.blake2b_init(this.pointer, this.digestLength)

  if (key) {
    this.update(key)
    this._memory.fill(0, head, head + key.length) // whiteout key
    this._memory[this.pointer + 200] = 128
  }
}

Blake2b.prototype._realloc = function (size) {
  wasm.memory.grow(Math.max(0, Math.ceil(Math.abs(size - this._memory.length) / 65536)))
  this._memory = new Uint8Array(wasm.memory.buffer)
}

Blake2b.prototype.update = function (input) {
  assert(this.finalized === false, 'Hash instance finalized')
  assert(input instanceof Uint8Array, 'input must be Uint8Array or Buffer')

  if (head + input.length > this._memory.length) this._realloc(head + input.length)
  this._memory.set(input, head)
  wasm.blake2b_update(this.pointer, head, head + input.length)
  return this
}

Blake2b.prototype.digest = function (enc) {
  assert(this.finalized === false, 'Hash instance finalized')
  this.finalized = true

  freeList.push(this.pointer)
  wasm.blake2b_final(this.pointer)

  if (!enc || enc === 'binary') {
    return this._memory.slice(this.pointer + 128, this.pointer + 128 + this.digestLength)
  }

  if (typeof enc === 'string') {
    return b4a.toString(this._memory, enc, this.pointer + 128, this.pointer + 128 + this.digestLength)
  }

  assert(enc instanceof Uint8Array && enc.length >= this.digestLength, 'input must be Uint8Array or Buffer')
  for (var i = 0; i < this.digestLength; i++) {
    enc[i] = this._memory[this.pointer + 128 + i]
  }

  return enc
}

// libsodium compat
Blake2b.prototype.final = Blake2b.prototype.digest

Blake2b.WASM = wasm
Blake2b.SUPPORTED = typeof WebAssembly !== 'undefined'

Blake2b.ready = function (cb) {
  if (!cb) cb = noop
  if (!wasmPromise) return cb(new Error('WebAssembly not supported'))
  return wasmPromise.then(() => cb(), cb)
}

Blake2b.prototype.ready = Blake2b.ready

Blake2b.prototype.getPartialHash = function () {
  return this._memory.slice(this.pointer, this.pointer + 216);
}

Blake2b.prototype.setPartialHash = function (ph) {
  this._memory.set(ph, this.pointer);
}

function noop () {}

},{"./blake2b":11,"b4a":4,"nanoassert":51}],13:[function(require,module,exports){
var assert = require('nanoassert')
var b2wasm = require('blake2b-wasm')

// 64-bit unsigned addition
// Sets v[a,a+1] += v[b,b+1]
// v should be a Uint32Array
function ADD64AA (v, a, b) {
  var o0 = v[a] + v[b]
  var o1 = v[a + 1] + v[b + 1]
  if (o0 >= 0x100000000) {
    o1++
  }
  v[a] = o0
  v[a + 1] = o1
}

// 64-bit unsigned addition
// Sets v[a,a+1] += b
// b0 is the low 32 bits of b, b1 represents the high 32 bits
function ADD64AC (v, a, b0, b1) {
  var o0 = v[a] + b0
  if (b0 < 0) {
    o0 += 0x100000000
  }
  var o1 = v[a + 1] + b1
  if (o0 >= 0x100000000) {
    o1++
  }
  v[a] = o0
  v[a + 1] = o1
}

// Little-endian byte access
function B2B_GET32 (arr, i) {
  return (arr[i] ^
  (arr[i + 1] << 8) ^
  (arr[i + 2] << 16) ^
  (arr[i + 3] << 24))
}

// G Mixing function
// The ROTRs are inlined for speed
function B2B_G (a, b, c, d, ix, iy) {
  var x0 = m[ix]
  var x1 = m[ix + 1]
  var y0 = m[iy]
  var y1 = m[iy + 1]

  ADD64AA(v, a, b) // v[a,a+1] += v[b,b+1] ... in JS we must store a uint64 as two uint32s
  ADD64AC(v, a, x0, x1) // v[a, a+1] += x ... x0 is the low 32 bits of x, x1 is the high 32 bits

  // v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated to the right by 32 bits
  var xor0 = v[d] ^ v[a]
  var xor1 = v[d + 1] ^ v[a + 1]
  v[d] = xor1
  v[d + 1] = xor0

  ADD64AA(v, c, d)

  // v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 24 bits
  xor0 = v[b] ^ v[c]
  xor1 = v[b + 1] ^ v[c + 1]
  v[b] = (xor0 >>> 24) ^ (xor1 << 8)
  v[b + 1] = (xor1 >>> 24) ^ (xor0 << 8)

  ADD64AA(v, a, b)
  ADD64AC(v, a, y0, y1)

  // v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated right by 16 bits
  xor0 = v[d] ^ v[a]
  xor1 = v[d + 1] ^ v[a + 1]
  v[d] = (xor0 >>> 16) ^ (xor1 << 16)
  v[d + 1] = (xor1 >>> 16) ^ (xor0 << 16)

  ADD64AA(v, c, d)

  // v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 63 bits
  xor0 = v[b] ^ v[c]
  xor1 = v[b + 1] ^ v[c + 1]
  v[b] = (xor1 >>> 31) ^ (xor0 << 1)
  v[b + 1] = (xor0 >>> 31) ^ (xor1 << 1)
}

// Initialization Vector
var BLAKE2B_IV32 = new Uint32Array([
  0xF3BCC908, 0x6A09E667, 0x84CAA73B, 0xBB67AE85,
  0xFE94F82B, 0x3C6EF372, 0x5F1D36F1, 0xA54FF53A,
  0xADE682D1, 0x510E527F, 0x2B3E6C1F, 0x9B05688C,
  0xFB41BD6B, 0x1F83D9AB, 0x137E2179, 0x5BE0CD19
])

var SIGMA8 = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
  12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
  13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
  10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
]

// These are offsets into a uint64 buffer.
// Multiply them all by 2 to make them offsets into a uint32 buffer,
// because this is Javascript and we don't have uint64s
var SIGMA82 = new Uint8Array(SIGMA8.map(function (x) { return x * 2 }))

// Compression function. 'last' flag indicates last block.
// Note we're representing 16 uint64s as 32 uint32s
var v = new Uint32Array(32)
var m = new Uint32Array(32)
function blake2bCompress (ctx, last) {
  var i = 0

  // init work variables
  for (i = 0; i < 16; i++) {
    v[i] = ctx.h[i]
    v[i + 16] = BLAKE2B_IV32[i]
  }

  // low 64 bits of offset
  v[24] = v[24] ^ ctx.t
  v[25] = v[25] ^ (ctx.t / 0x100000000)
  // high 64 bits not supported, offset may not be higher than 2**53-1

  // last block flag set ?
  if (last) {
    v[28] = ~v[28]
    v[29] = ~v[29]
  }

  // get little-endian words
  for (i = 0; i < 32; i++) {
    m[i] = B2B_GET32(ctx.b, 4 * i)
  }

  // twelve rounds of mixing
  for (i = 0; i < 12; i++) {
    B2B_G(0, 8, 16, 24, SIGMA82[i * 16 + 0], SIGMA82[i * 16 + 1])
    B2B_G(2, 10, 18, 26, SIGMA82[i * 16 + 2], SIGMA82[i * 16 + 3])
    B2B_G(4, 12, 20, 28, SIGMA82[i * 16 + 4], SIGMA82[i * 16 + 5])
    B2B_G(6, 14, 22, 30, SIGMA82[i * 16 + 6], SIGMA82[i * 16 + 7])
    B2B_G(0, 10, 20, 30, SIGMA82[i * 16 + 8], SIGMA82[i * 16 + 9])
    B2B_G(2, 12, 22, 24, SIGMA82[i * 16 + 10], SIGMA82[i * 16 + 11])
    B2B_G(4, 14, 16, 26, SIGMA82[i * 16 + 12], SIGMA82[i * 16 + 13])
    B2B_G(6, 8, 18, 28, SIGMA82[i * 16 + 14], SIGMA82[i * 16 + 15])
  }

  for (i = 0; i < 16; i++) {
    ctx.h[i] = ctx.h[i] ^ v[i] ^ v[i + 16]
  }
}

// reusable parameter_block
var parameter_block = new Uint8Array([
  0, 0, 0, 0,      //  0: outlen, keylen, fanout, depth
  0, 0, 0, 0,      //  4: leaf length, sequential mode
  0, 0, 0, 0,      //  8: node offset
  0, 0, 0, 0,      // 12: node offset
  0, 0, 0, 0,      // 16: node depth, inner length, rfu
  0, 0, 0, 0,      // 20: rfu
  0, 0, 0, 0,      // 24: rfu
  0, 0, 0, 0,      // 28: rfu
  0, 0, 0, 0,      // 32: salt
  0, 0, 0, 0,      // 36: salt
  0, 0, 0, 0,      // 40: salt
  0, 0, 0, 0,      // 44: salt
  0, 0, 0, 0,      // 48: personal
  0, 0, 0, 0,      // 52: personal
  0, 0, 0, 0,      // 56: personal
  0, 0, 0, 0       // 60: personal
])

// Creates a BLAKE2b hashing context
// Requires an output length between 1 and 64 bytes
// Takes an optional Uint8Array key
function Blake2b (outlen, key, salt, personal) {
  // zero out parameter_block before usage
  parameter_block.fill(0)
  // state, 'param block'

  this.b = new Uint8Array(128)
  this.h = new Uint32Array(16)
  this.t = 0 // input count
  this.c = 0 // pointer within buffer
  this.outlen = outlen // output length in bytes

  parameter_block[0] = outlen
  if (key) parameter_block[1] = key.length
  parameter_block[2] = 1 // fanout
  parameter_block[3] = 1 // depth

  if (salt) parameter_block.set(salt, 32)
  if (personal) parameter_block.set(personal, 48)

  // initialize hash state
  for (var i = 0; i < 16; i++) {
    this.h[i] = BLAKE2B_IV32[i] ^ B2B_GET32(parameter_block, i * 4)
  }

  // key the hash, if applicable
  if (key) {
    blake2bUpdate(this, key)
    // at the end
    this.c = 128
  }
}

Blake2b.prototype.update = function (input) {
  assert(input instanceof Uint8Array, 'input must be Uint8Array or Buffer')
  blake2bUpdate(this, input)
  return this
}

Blake2b.prototype.digest = function (out) {
  var buf = (!out || out === 'binary' || out === 'hex') ? new Uint8Array(this.outlen) : out
  assert(buf instanceof Uint8Array, 'out must be "binary", "hex", Uint8Array, or Buffer')
  assert(buf.length >= this.outlen, 'out must have at least outlen bytes of space')
  blake2bFinal(this, buf)
  if (out === 'hex') return hexSlice(buf)
  return buf
}

Blake2b.prototype.final = Blake2b.prototype.digest

Blake2b.ready = function (cb) {
  b2wasm.ready(function () {
    cb() // ignore the error
  })
}

// Updates a BLAKE2b streaming hash
// Requires hash context and Uint8Array (byte array)
function blake2bUpdate (ctx, input) {
  for (var i = 0; i < input.length; i++) {
    if (ctx.c === 128) { // buffer full ?
      ctx.t += ctx.c // add counters
      blake2bCompress(ctx, false) // compress (not last)
      ctx.c = 0 // counter to zero
    }
    ctx.b[ctx.c++] = input[i]
  }
}

// Completes a BLAKE2b streaming hash
// Returns a Uint8Array containing the message digest
function blake2bFinal (ctx, out) {
  ctx.t += ctx.c // mark last block offset

  while (ctx.c < 128) { // fill up with zeros
    ctx.b[ctx.c++] = 0
  }
  blake2bCompress(ctx, true) // final block flag = 1

  for (var i = 0; i < ctx.outlen; i++) {
    out[i] = ctx.h[i >> 2] >> (8 * (i & 3))
  }
  return out
}

function hexSlice (buf) {
  var str = ''
  for (var i = 0; i < buf.length; i++) str += toHex(buf[i])
  return str
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

var Proto = Blake2b

module.exports = function createHash (outlen, key, salt, personal, noAssert) {
  if (noAssert !== true) {
    assert(outlen >= BYTES_MIN, 'outlen must be at least ' + BYTES_MIN + ', was given ' + outlen)
    assert(outlen <= BYTES_MAX, 'outlen must be at most ' + BYTES_MAX + ', was given ' + outlen)
    if (key != null) {
      assert(key instanceof Uint8Array, 'key must be Uint8Array or Buffer')
      assert(key.length >= KEYBYTES_MIN, 'key must be at least ' + KEYBYTES_MIN + ', was given ' + key.length)
      assert(key.length <= KEYBYTES_MAX, 'key must be at most ' + KEYBYTES_MAX + ', was given ' + key.length)
    }
    if (salt != null) {
      assert(salt instanceof Uint8Array, 'salt must be Uint8Array or Buffer')
      assert(salt.length === SALTBYTES, 'salt must be exactly ' + SALTBYTES + ', was given ' + salt.length)
    }
    if (personal != null) {
      assert(personal instanceof Uint8Array, 'personal must be Uint8Array or Buffer')
      assert(personal.length === PERSONALBYTES, 'personal must be exactly ' + PERSONALBYTES + ', was given ' + personal.length)
    }
  }

  return new Proto(outlen, key, salt, personal)
}

module.exports.ready = function (cb) {
  b2wasm.ready(function () { // ignore errors
    cb()
  })
}

module.exports.WASM_SUPPORTED = b2wasm.SUPPORTED
module.exports.WASM_LOADED = false

var BYTES_MIN = module.exports.BYTES_MIN = 16
var BYTES_MAX = module.exports.BYTES_MAX = 64
var BYTES = module.exports.BYTES = 32
var KEYBYTES_MIN = module.exports.KEYBYTES_MIN = 16
var KEYBYTES_MAX = module.exports.KEYBYTES_MAX = 64
var KEYBYTES = module.exports.KEYBYTES = 32
var SALTBYTES = module.exports.SALTBYTES = 16
var PERSONALBYTES = module.exports.PERSONALBYTES = 16

b2wasm.ready(function (err) {
  if (!err) {
    module.exports.WASM_LOADED = true
    module.exports = b2wasm
  }
})

},{"blake2b-wasm":12,"nanoassert":51}],14:[function(require,module,exports){
const assert = require('nanoassert')

module.exports = Chacha20

const constant = [1634760805, 857760878, 2036477234, 1797285236]

function Chacha20 (nonce, key, counter) {
  assert(key.byteLength === 32)
  assert(nonce.byteLength === 8 || nonce.byteLength === 12)

  const n = new Uint32Array(nonce.buffer, nonce.byteOffset, nonce.byteLength / 4)
  const k = new Uint32Array(key.buffer, key.byteOffset, key.byteLength / 4)

  if (!counter) counter = 0
  assert(counter < Number.MAX_SAFE_INTEGER)

  this.finalized = false
  this.pos = 0
  this.state = new Uint32Array(16)

  for (let i = 0; i < 4; i++) this.state[i] = constant[i]
  for (let i = 0; i < 8; i++) this.state[4 + i] = k[i]

  this.state[12] = counter & 0xffffffff

  if (n.byteLength === 8) {
    this.state[13] = (counter && 0xffffffff00000000) >> 32
    this.state[14] = n[0]
    this.state[15] = n[1]
  } else {
    this.state[13] = n[0]
    this.state[14] = n[1]
    this.state[15] = n[2]
  }

  return this
}

Chacha20.prototype.update = function (output, input) {
  assert(!this.finalized, 'cipher finalized.')
  assert(output.byteLength >= input.byteLength,
    'output cannot be shorter than input.')

  let len = input.length
  let offset = this.pos % 64
  this.pos += len

  // input position
  let j = 0

  let keyStream = chacha20Block(this.state)

  // try to finsih the current block
  while (offset > 0 && len > 0) {
    output[j] = input[j++] ^ keyStream[offset]
    offset = (offset + 1) & 0x3f
    if (!offset) this.state[12]++
    len--
  }

  // encrypt rest block at a time
  while (len > 0) {
    keyStream = chacha20Block(this.state)

    // less than a full block remaining
    if (len < 64) {
      for (let i = 0; i < len; i++) {
        output[j] = input[j++] ^ keyStream[offset++]
        offset &= 0x3f
      }

      return
    }

    for (; offset < 64;) {
      output[j] = input[j++] ^ keyStream[offset++]
    }

    this.state[12]++
    offset = 0
    len -= 64
  }
}

Chacha20.prototype.final = function () {
  this.state.fill(0)
  this.pos = 0
  this.finalized = true
}

function chacha20Block (state) {
  // working state
  const ws = new Uint32Array(16)
  for (let i = 16; i--;) ws[i] = state[i]

  for (let i = 0; i < 20; i += 2) {
    QR(ws, 0, 4, 8, 12) // column 0
    QR(ws, 1, 5, 9, 13) // column 1
    QR(ws, 2, 6, 10, 14) // column 2
    QR(ws, 3, 7, 11, 15) // column 3

    QR(ws, 0, 5, 10, 15) // diagonal 1 (main diagonal)
    QR(ws, 1, 6, 11, 12) // diagonal 2
    QR(ws, 2, 7, 8, 13) // diagonal 3
    QR(ws, 3, 4, 9, 14) // diagonal 4
  }

  for (let i = 0; i < 16; i++) {
    ws[i] += state[i]
  }

  return new Uint8Array(ws.buffer, ws.byteOffset, ws.byteLength)
}

function rotl (a, b) {
  return ((a << b) | (a >>> (32 - b)))
}

function QR (obj, a, b, c, d) {
  obj[a] += obj[b]
  obj[d] ^= obj[a]
  obj[d] = rotl(obj[d], 16)

  obj[c] += obj[d]
  obj[b] ^= obj[c]
  obj[b] = rotl(obj[b], 12)

  obj[a] += obj[b]
  obj[d] ^= obj[a]
  obj[d] = rotl(obj[d], 8)

  obj[c] += obj[d]
  obj[b] ^= obj[c]
  obj[b] = rotl(obj[b], 7)
}

},{"nanoassert":51}],15:[function(require,module,exports){
const LE = exports.LE = (new Uint8Array(new Uint16Array([0xff]).buffer))[0] === 0xff

exports.BE = !LE

},{}],16:[function(require,module,exports){
const b4a = require('b4a')

const { BE } = require('./endian')

exports.state = function (start = 0, end = 0, buffer = null) {
  return { start, end, buffer, cache: null }
}

const raw = exports.raw = require('./raw')

const uint = exports.uint = {
  preencode (state, n) {
    state.end += n <= 0xfc ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9
  },
  encode (state, n) {
    if (n <= 0xfc) uint8.encode(state, n)
    else if (n <= 0xffff) {
      state.buffer[state.start++] = 0xfd
      uint16.encode(state, n)
    } else if (n <= 0xffffffff) {
      state.buffer[state.start++] = 0xfe
      uint32.encode(state, n)
    } else {
      state.buffer[state.start++] = 0xff
      uint64.encode(state, n)
    }
  },
  decode (state) {
    const a = uint8.decode(state)
    if (a <= 0xfc) return a
    if (a === 0xfd) return uint16.decode(state)
    if (a === 0xfe) return uint32.decode(state)
    return uint64.decode(state)
  }
}

const uint8 = exports.uint8 = {
  preencode (state, n) {
    state.end += 1
  },
  encode (state, n) {
    state.buffer[state.start++] = n
  },
  decode (state) {
    if (state.start >= state.end) throw new Error('Out of bounds')
    return state.buffer[state.start++]
  }
}

const uint16 = exports.uint16 = {
  preencode (state, n) {
    state.end += 2
  },
  encode (state, n) {
    state.buffer[state.start++] = n
    state.buffer[state.start++] = n >>> 8
  },
  decode (state) {
    if (state.end - state.start < 2) throw new Error('Out of bounds')
    return (
      state.buffer[state.start++] +
      state.buffer[state.start++] * 0x100
    )
  }
}

const uint24 = exports.uint24 = {
  preencode (state, n) {
    state.end += 3
  },
  encode (state, n) {
    state.buffer[state.start++] = n
    state.buffer[state.start++] = n >>> 8
    state.buffer[state.start++] = n >>> 16
  },
  decode (state) {
    if (state.end - state.start < 3) throw new Error('Out of bounds')
    return (
      state.buffer[state.start++] +
      state.buffer[state.start++] * 0x100 +
      state.buffer[state.start++] * 0x10000
    )
  }
}

const uint32 = exports.uint32 = {
  preencode (state, n) {
    state.end += 4
  },
  encode (state, n) {
    state.buffer[state.start++] = n
    state.buffer[state.start++] = n >>> 8
    state.buffer[state.start++] = n >>> 16
    state.buffer[state.start++] = n >>> 24
  },
  decode (state) {
    if (state.end - state.start < 4) throw new Error('Out of bounds')
    return (
      state.buffer[state.start++] +
      state.buffer[state.start++] * 0x100 +
      state.buffer[state.start++] * 0x10000 +
      state.buffer[state.start++] * 0x1000000
    )
  }
}

const uint40 = exports.uint40 = {
  preencode (state, n) {
    state.end += 5
  },
  encode (state, n) {
    const r = Math.floor(n / 0x100)
    uint8.encode(state, n)
    uint32.encode(state, r)
  },
  decode (state) {
    if (state.end - state.start < 5) throw new Error('Out of bounds')
    return uint8.decode(state) + 0x100 * uint32.decode(state)
  }
}

const uint48 = exports.uint48 = {
  preencode (state, n) {
    state.end += 6
  },
  encode (state, n) {
    const r = Math.floor(n / 0x10000)
    uint16.encode(state, n)
    uint32.encode(state, r)
  },
  decode (state) {
    if (state.end - state.start < 6) throw new Error('Out of bounds')
    return uint16.decode(state) + 0x10000 * uint32.decode(state)
  }
}

const uint56 = exports.uint56 = {
  preencode (state, n) {
    state.end += 7
  },
  encode (state, n) {
    const r = Math.floor(n / 0x1000000)
    uint24.encode(state, n)
    uint32.encode(state, r)
  },
  decode (state) {
    if (state.end - state.start < 7) throw new Error('Out of bounds')
    return uint24.decode(state) + 0x1000000 * uint32.decode(state)
  }
}

const uint64 = exports.uint64 = {
  preencode (state, n) {
    state.end += 8
  },
  encode (state, n) {
    const r = Math.floor(n / 0x100000000)
    uint32.encode(state, n)
    uint32.encode(state, r)
  },
  decode (state) {
    if (state.end - state.start < 8) throw new Error('Out of bounds')
    return uint32.decode(state) + 0x100000000 * uint32.decode(state)
  }
}

exports.int = zigZag(uint)
exports.int8 = zigZag(uint8)
exports.int16 = zigZag(uint16)
exports.int24 = zigZag(uint24)
exports.int32 = zigZag(uint32)
exports.int40 = zigZag(uint40)
exports.int48 = zigZag(uint48)
exports.int56 = zigZag(uint56)
exports.int64 = zigZag(uint64)

exports.lexint = require('./lexint')

exports.float32 = {
  preencode (state, n) {
    state.end += 4
  },
  encode (state, n) {
    const view = new DataView(state.buffer.buffer, state.start + state.buffer.byteOffset, 4)
    view.setFloat32(0, n, true) // little endian
    state.start += 4
  },
  decode (state) {
    if (state.end - state.start < 4) throw new Error('Out of bounds')
    const view = new DataView(state.buffer.buffer, state.start + state.buffer.byteOffset, 4)
    const float = view.getFloat32(0, true) // little endian
    state.start += 4
    return float
  }
}

exports.float64 = {
  preencode (state, n) {
    state.end += 8
  },
  encode (state, n) {
    const view = new DataView(state.buffer.buffer, state.start + state.buffer.byteOffset, 8)
    view.setFloat64(0, n, true) // little endian
    state.start += 8
  },
  decode (state) {
    if (state.end - state.start < 8) throw new Error('Out of bounds')
    const view = new DataView(state.buffer.buffer, state.start + state.buffer.byteOffset, 8)
    const float = view.getFloat64(0, true) // little endian
    state.start += 8
    return float
  }
}

const buffer = exports.buffer = {
  preencode (state, b) {
    if (b) uint8array.preencode(state, b)
    else state.end++
  },
  encode (state, b) {
    if (b) uint8array.encode(state, b)
    else state.buffer[state.start++] = 0
  },
  decode (state) {
    const len = uint.decode(state)
    if (len === 0) return null
    if (state.end - state.start < len) throw new Error('Out of bounds')
    return state.buffer.subarray(state.start, (state.start += len))
  }
}

exports.binary = {
  ...buffer,
  preencode (state, b) {
    if (typeof b === 'string') utf8.preencode(state, b)
    else buffer.preencode(state, b)
  },
  encode (state, b) {
    if (typeof b === 'string') utf8.encode(state, b)
    else buffer.encode(state, b)
  }
}

function typedarray (TypedArray, swap) {
  const n = TypedArray.BYTES_PER_ELEMENT

  return {
    preencode (state, b) {
      uint.preencode(state, b.length)
      state.end += b.byteLength
    },
    encode (state, b) {
      uint.encode(state, b.length)

      const view = new Uint8Array(b.buffer, b.byteOffset, b.byteLength)

      if (BE && swap) swap(view)

      state.buffer.set(view, state.start)
      state.start += b.byteLength
    },
    decode (state) {
      const len = uint.decode(state)

      let b = state.buffer.subarray(state.start, state.start += len * n)
      if (b.byteLength !== len * n) throw new Error('Out of bounds')
      if ((b.byteOffset % n) !== 0) b = new Uint8Array(b)

      if (BE && swap) swap(b)

      return new TypedArray(b.buffer, b.byteOffset, b.byteLength / n)
    }
  }
}

const uint8array = exports.uint8array = typedarray(Uint8Array)
exports.uint16array = typedarray(Uint16Array, b4a.swap16)
exports.uint32array = typedarray(Uint32Array, b4a.swap32)

exports.int8array = typedarray(Int8Array)
exports.int16array = typedarray(Int16Array, b4a.swap16)
exports.int32array = typedarray(Int32Array, b4a.swap32)

exports.float32array = typedarray(Float32Array, b4a.swap32)
exports.float64array = typedarray(Float64Array, b4a.swap64)

function string (encoding) {
  return {
    preencode (state, s) {
      const len = b4a.byteLength(s, encoding)
      uint.preencode(state, len)
      state.end += len
    },
    encode (state, s) {
      const len = b4a.byteLength(s, encoding)
      uint.encode(state, len)
      b4a.write(state.buffer, s, state.start, encoding)
      state.start += len
    },
    decode (state) {
      const len = uint.decode(state)
      if (state.end - state.start < len) throw new Error('Out of bounds')
      return b4a.toString(state.buffer, encoding, state.start, (state.start += len))
    },
    fixed (n) {
      return {
        preencode (state) {
          state.end += n
        },
        encode (state, s) {
          b4a.write(state.buffer, s, state.start, n, encoding)
          state.start += n
        },
        decode (state) {
          if (state.end - state.start < n) throw new Error('Out of bounds')
          return b4a.toString(state.buffer, encoding, state.start, (state.start += n))
        }
      }
    }
  }
}

const utf8 = exports.string = exports.utf8 = string('utf-8')
exports.ascii = string('ascii')
exports.hex = string('hex')
exports.base64 = string('base64')
exports.ucs2 = exports.utf16le = string('utf16le')

exports.bool = {
  preencode (state, b) {
    state.end++
  },
  encode (state, b) {
    state.buffer[state.start++] = b ? 1 : 0
  },
  decode (state) {
    if (state.start >= state.end) throw Error('Out of bounds')
    return state.buffer[state.start++] === 1
  }
}

const fixed = exports.fixed = function fixed (n) {
  return {
    preencode (state, s) {
      state.end += n
    },
    encode (state, s) {
      state.buffer.set(s, state.start)
      state.start += n
    },
    decode (state) {
      if (state.end - state.start < n) throw new Error('Out of bounds')
      return state.buffer.subarray(state.start, (state.start += n))
    }
  }
}

exports.fixed32 = fixed(32)
exports.fixed64 = fixed(64)

exports.array = function array (enc) {
  return {
    preencode (state, list) {
      uint.preencode(state, list.length)
      for (let i = 0; i < list.length; i++) enc.preencode(state, list[i])
    },
    encode (state, list) {
      uint.encode(state, list.length)
      for (let i = 0; i < list.length; i++) enc.encode(state, list[i])
    },
    decode (state) {
      const len = uint.decode(state)
      if (len > 0x100000) throw new Error('Array is too big')
      const arr = new Array(len)
      for (let i = 0; i < len; i++) arr[i] = enc.decode(state)
      return arr
    }
  }
}

exports.json = {
  preencode (state, v) {
    utf8.preencode(state, JSON.stringify(v))
  },
  encode (state, v) {
    utf8.encode(state, JSON.stringify(v))
  },
  decode (state) {
    return JSON.parse(utf8.decode(state))
  }
}

exports.ndjson = {
  preencode (state, v) {
    utf8.preencode(state, JSON.stringify(v) + '\n')
  },
  encode (state, v) {
    utf8.encode(state, JSON.stringify(v) + '\n')
  },
  decode (state) {
    return JSON.parse(utf8.decode(state))
  }
}

// simple helper for when you want to just express nothing
exports.none = {
  preencode (state, n) {
    // do nothing
  },
  encode (state, n) {
    // do nothing
  },
  decode (state) {
    return null
  }
}

// "any" encoders here for helping just structure any object without schematising it

const anyArray = {
  preencode (state, arr) {
    uint.preencode(state, arr.length)
    for (let i = 0; i < arr.length; i++) {
      any.preencode(state, arr[i])
    }
  },
  encode (state, arr) {
    uint.encode(state, arr.length)
    for (let i = 0; i < arr.length; i++) {
      any.encode(state, arr[i])
    }
  },
  decode (state) {
    const arr = []
    let len = uint.decode(state)
    while (len-- > 0) {
      arr.push(any.decode(state))
    }
    return arr
  }
}

const anyObject = {
  preencode (state, o) {
    const keys = Object.keys(o)
    uint.preencode(state, keys.length)
    for (const key of keys) {
      utf8.preencode(state, key)
      any.preencode(state, o[key])
    }
  },
  encode (state, o) {
    const keys = Object.keys(o)
    uint.encode(state, keys.length)
    for (const key of keys) {
      utf8.encode(state, key)
      any.encode(state, o[key])
    }
  },
  decode (state) {
    let len = uint.decode(state)
    const o = {}
    while (len-- > 0) {
      const key = utf8.decode(state)
      o[key] = any.decode(state)
    }
    return o
  }
}

const anyTypes = [
  exports.none,
  exports.bool,
  exports.string,
  exports.buffer,
  exports.uint,
  exports.int,
  exports.float64,
  anyArray,
  anyObject
]

const any = exports.any = {
  preencode (state, o) {
    const t = getType(o)
    uint.preencode(state, t)
    anyTypes[t].preencode(state, o)
  },
  encode (state, o) {
    const t = getType(o)
    uint.encode(state, t)
    anyTypes[t].encode(state, o)
  },
  decode (state) {
    const t = uint.decode(state)
    if (t >= anyTypes.length) throw new Error('Unknown type: ' + t)
    return anyTypes[t].decode(state)
  }
}

function getType (o) {
  if (o === null || o === undefined) return 0
  if (typeof o === 'boolean') return 1
  if (typeof o === 'string') return 2
  if (b4a.isBuffer(o)) return 3
  if (typeof o === 'number') {
    if (Number.isInteger(o)) return o >= 0 ? 4 : 5
    return 6
  }
  if (Array.isArray(o)) return 7
  if (typeof o === 'object') return 8

  throw new Error('Unsupported type for ' + o)
}

exports.from = function from (enc) {
  if (typeof enc === 'string') return fromNamed(enc)
  if (enc.preencode) return enc
  if (enc.encodingLength) return fromAbstractEncoder(enc)
  return fromCodec(enc)
}

function fromNamed (enc) {
  switch (enc) {
    case 'ascii': return raw.ascii
    case 'utf-8':
    case 'utf8': return raw.utf8
    case 'hex': return raw.hex
    case 'base64': return raw.base64
    case 'utf16-le':
    case 'utf16le':
    case 'ucs-2':
    case 'ucs2': return raw.ucs2
    case 'ndjson': return raw.ndjson
    case 'json': return raw.json
    case 'binary':
    default: return raw.binary
  }
}

function fromCodec (enc) {
  let tmpM = null
  let tmpBuf = null

  return {
    preencode (state, m) {
      tmpM = m
      tmpBuf = enc.encode(m)
      state.end += tmpBuf.byteLength
    },
    encode (state, m) {
      raw.encode(state, m === tmpM ? tmpBuf : enc.encode(m))
      tmpM = tmpBuf = null
    },
    decode (state) {
      return enc.decode(raw.decode(state))
    }
  }
}

function fromAbstractEncoder (enc) {
  return {
    preencode (state, m) {
      state.end += enc.encodingLength(m)
    },
    encode (state, m) {
      enc.encode(m, state.buffer, state.start)
      state.start += enc.encode.bytes
    },
    decode (state) {
      const m = enc.decode(state.buffer, state.start, state.end)
      state.start += enc.decode.bytes
      return m
    }
  }
}

exports.encode = function encode (enc, m) {
  const state = exports.state()
  enc.preencode(state, m)
  state.buffer = b4a.allocUnsafe(state.end)
  enc.encode(state, m)
  return state.buffer
}

exports.decode = function decode (enc, buffer) {
  return enc.decode(exports.state(0, buffer.byteLength, buffer))
}

function zigZag (enc) {
  return {
    preencode (state, n) {
      enc.preencode(state, zigZagEncode(n))
    },
    encode (state, n) {
      enc.encode(state, zigZagEncode(n))
    },
    decode (state) {
      return zigZagDecode(enc.decode(state))
    }
  }
}

function zigZagDecode (n) {
  return n === 0 ? n : (n & 1) === 0 ? n / 2 : -(n + 1) / 2
}

function zigZagEncode (n) {
  // 0, -1, 1, -2, 2, ...
  return n < 0 ? (2 * -n) - 1 : n === 0 ? 0 : 2 * n
}

},{"./endian":15,"./lexint":17,"./raw":18,"b4a":4}],17:[function(require,module,exports){
module.exports = {
  preencode,
  encode,
  decode
}

function preencode (state, num) {
  if (num < 251) {
    state.end++
  } else if (num < 256) {
    state.end += 2
  } else if (num < 0x10000) {
    state.end += 3
  } else if (num < 0x1000000) {
    state.end += 4
  } else if (num < 0x100000000) {
    state.end += 5
  } else {
    state.end++
    const exp = Math.floor(Math.log(num) / Math.log(2)) - 32
    preencode(state, exp)
    state.end += 6
  }
}

function encode (state, num) {
  const max = 251
  const x = num - max

  if (num < max) {
    state.buffer[state.start++] = num
  } else if (num < 256) {
    state.buffer[state.start++] = max
    state.buffer[state.start++] = x
  } else if (num < 0x10000) {
    state.buffer[state.start++] = max + 1
    state.buffer[state.start++] = x >> 8 & 0xff
    state.buffer[state.start++] = x & 0xff
  } else if (num < 0x1000000) {
    state.buffer[state.start++] = max + 2
    state.buffer[state.start++] = x >> 16
    state.buffer[state.start++] = x >> 8 & 0xff
    state.buffer[state.start++] = x & 0xff
  } else if (num < 0x100000000) {
    state.buffer[state.start++] = max + 3
    state.buffer[state.start++] = x >> 24
    state.buffer[state.start++] = x >> 16 & 0xff
    state.buffer[state.start++] = x >> 8 & 0xff
    state.buffer[state.start++] = x & 0xff
  } else {
    // need to use Math here as bitwise ops are 32 bit
    const exp = Math.floor(Math.log(x) / Math.log(2)) - 32
    state.buffer[state.start++] = 0xff

    encode(state, exp)
    const rem = x / Math.pow(2, exp - 11)

    for (let i = 5; i >= 0; i--) {
      state.buffer[state.start++] = rem / Math.pow(2, 8 * i) & 0xff
    }
  }
}

function decode (state) {
  const max = 251

  if (state.end - state.start < 1) throw new Error('Out of bounds')

  const flag = state.buffer[state.start++]

  if (flag < max) return flag

  if (state.end - state.start < flag - max + 1) {
    throw new Error('Out of bounds.')
  }

  if (flag < 252) {
    return state.buffer[state.start++] +
      max
  }

  if (flag < 253) {
    return (state.buffer[state.start++] << 8) +
      state.buffer[state.start++] +
      max
  }

  if (flag < 254) {
    return (state.buffer[state.start++] << 16) +
      (state.buffer[state.start++] << 8) +
      state.buffer[state.start++] +
      max
  }

  // << 24 result may be interpreted as negative
  if (flag < 255) {
    return (state.buffer[state.start++] * 0x1000000) +
      (state.buffer[state.start++] << 16) +
      (state.buffer[state.start++] << 8) +
      state.buffer[state.start++] +
      max
  }

  const exp = decode(state)

  if (state.end - state.start < 6) throw new Error('Out of bounds')

  let rem = 0
  for (let i = 5; i >= 0; i--) {
    rem += state.buffer[state.start++] * Math.pow(2, 8 * i)
  }

  return (rem * Math.pow(2, exp - 11)) + max
}

},{}],18:[function(require,module,exports){
const b4a = require('b4a')

const { BE } = require('./endian')

exports = module.exports = {
  preencode (state, b) {
    state.end += b.byteLength
  },
  encode (state, b) {
    state.buffer.set(b, state.start)
    state.start += b.byteLength
  },
  decode (state) {
    const b = state.buffer.subarray(state.start, state.end)
    state.start = state.end
    return b
  }
}

const buffer = exports.buffer = {
  preencode (state, b) {
    if (b) uint8array.preencode(state, b)
    else state.end++
  },
  encode (state, b) {
    if (b) uint8array.encode(state, b)
    else state.buffer[state.start++] = 0
  },
  decode (state) {
    const b = state.buffer.subarray(state.start)
    if (b.byteLength === 0) return null
    state.start = state.end
    return b
  }
}

exports.binary = {
  ...buffer,
  preencode (state, b) {
    if (typeof b === 'string') utf8.preencode(state, b)
    else buffer.preencode(state, b)
  },
  encode (state, b) {
    if (typeof b === 'string') utf8.encode(state, b)
    else buffer.encode(state, b)
  }
}

function typedarray (TypedArray, swap) {
  const n = TypedArray.BYTES_PER_ELEMENT

  return {
    preencode (state, b) {
      state.end += b.byteLength
    },
    encode (state, b) {
      const view = new Uint8Array(b.buffer, b.byteOffset, b.byteLength)

      if (BE && swap) swap(view)

      state.buffer.set(view, state.start)
      state.start += b.byteLength
    },
    decode (state) {
      let b = state.buffer.subarray(state.start)
      if ((b.byteOffset % n) !== 0) b = new Uint8Array(b)

      if (BE && swap) swap(b)

      state.start = state.end

      return new TypedArray(b.buffer, b.byteOffset, b.byteLength / n)
    }
  }
}

const uint8array = exports.uint8array = typedarray(Uint8Array)
exports.uint16array = typedarray(Uint16Array, b4a.swap16)
exports.uint32array = typedarray(Uint32Array, b4a.swap32)

exports.int8array = typedarray(Int8Array)
exports.int16array = typedarray(Int16Array, b4a.swap16)
exports.int32array = typedarray(Int32Array, b4a.swap32)

exports.float32array = typedarray(Float32Array, b4a.swap32)
exports.float64array = typedarray(Float64Array, b4a.swap64)

function string (encoding) {
  return {
    preencode (state, s) {
      state.end += b4a.byteLength(s, encoding)
    },
    encode (state, s) {
      state.start += b4a.write(state.buffer, s, state.start, encoding)
    },
    decode (state) {
      const s = b4a.toString(state.buffer, encoding, state.start)
      state.start = state.end
      return s
    }
  }
}

const utf8 = exports.string = exports.utf8 = string('utf-8')
exports.ascii = string('ascii')
exports.hex = string('hex')
exports.base64 = string('base64')
exports.ucs2 = exports.utf16le = string('utf16le')

exports.array = function array (enc) {
  return {
    preencode (state, list) {
      for (const value of list) enc.preencode(state, value)
    },
    encode (state, list) {
      for (const value of list) enc.encode(state, value)
    },
    decode (state) {
      const arr = []
      while (state.start < state.end) arr.push(enc.decode(state))
      return arr
    }
  }
}

exports.json = {
  preencode (state, v) {
    utf8.preencode(state, JSON.stringify(v))
  },
  encode (state, v) {
    utf8.encode(state, JSON.stringify(v))
  },
  decode (state) {
    return JSON.parse(utf8.decode(state))
  }
}

exports.ndjson = {
  preencode (state, v) {
    utf8.preencode(state, JSON.stringify(v) + '\n')
  },
  encode (state, v) {
    utf8.encode(state, JSON.stringify(v) + '\n')
  },
  decode (state) {
    return JSON.parse(utf8.decode(state))
  }
}

},{"./endian":15,"b4a":4}],19:[function(require,module,exports){
const safetyCatch = require('safety-catch')
const crypto = require('hypercore-crypto')
const sodium = require('sodium-universal')
const Hypercore = require('hypercore')
const hypercoreId = require('hypercore-id-encoding')
const Xache = require('xache')
const b4a = require('b4a')
const ReadyResource = require('ready-resource')
const RW = require('read-write-mutexify')

const [NS] = crypto.namespace('corestore', 1)
const DEFAULT_NAMESPACE = b4a.alloc(32) // This is meant to be 32 0-bytes

const CORES_DIR = 'cores'
const PRIMARY_KEY_FILE_NAME = 'primary-key'
const USERDATA_NAME_KEY = 'corestore/name'
const USERDATA_NAMESPACE_KEY = 'corestore/namespace'
const POOL_SIZE = 512 // how many open fds to aim for before cycling them

module.exports = class Corestore extends ReadyResource {
  constructor (storage, opts = {}) {
    super()
    const root = opts._root
    if(opts.storagefn){
       this.storage = opts.storagefn(storage, { lock: PRIMARY_KEY_FILE_NAME, poolSize: opts.poolSize || POOL_SIZE, rmdir: true })
    }else{
      this.storage = Hypercore.defaultStorage(storage, { lock: PRIMARY_KEY_FILE_NAME, poolSize: opts.poolSize || POOL_SIZE, rmdir: true })
    }
    this.cores = root ? root.cores : new Map()
    this.cache = !!opts.cache
    this.primaryKey = opts.primaryKey || null
    this.passive = !!opts.passive

    this._keyStorage = null
    this._bootstrap = opts._bootstrap || null
    this._namespace = opts.namespace || DEFAULT_NAMESPACE

    this._root = root || this
    this._replicationStreams = root ? root._replicationStreams : []
    this._overwrite = opts.overwrite === true
    this._readonly = opts.writable === false
    this._attached = opts._attached || null
    this._notDownloadingLinger = opts.notDownloadingLinger

    this._sessions = new Set() // sessions for THIS namespace
    this._rootStoreSessions = new Set()
    this._locks = root ? root._locks : new Map()

    this._findingPeersCount = 0
    this._findingPeers = []
    this._isCorestore = true

    if (this._namespace.byteLength !== 32) throw new Error('Namespace must be a 32-byte Buffer or Uint8Array')
    this.ready().catch(safetyCatch)
  }

  static isCorestore (obj) {
    return !!(typeof obj === 'object' && obj && obj._isCorestore)
  }

  static from (storage, opts) {
    return this.isCorestore(storage) ? storage : new this(storage, opts)
  }

  // for now just release the lock...
  async suspend () {
    if (this._root !== this) return this._root.suspend()

    await this.ready()

    if (this._keyStorage !== null) {
      await new Promise((resolve, reject) => {
        this._keyStorage.suspend((err) => {
          if (err) return reject(err)
          resolve()
        })
      })
    }
  }

  async resume () {
    if (this._root !== this) return this._root.resume()

    await this.ready()

    if (this._keyStorage !== null) {
      await new Promise((resolve, reject) => {
        this._keyStorage.open((err) => {
          if (err) return reject(err)
          resolve()
        })
      })
    }
  }

  findingPeers () {
    let done = false
    this._incFindingPeers()

    return () => {
      if (done) return
      done = true
      this._decFindingPeers()
    }
  }

  _emitCore (name, core) {
    this.emit(name, core)
    for (const session of this._root._rootStoreSessions) {
      if (session !== this) {
        session.emit(name, core)
      }
    }
    if (this !== this._root) this._root.emit(name, core)
  }

  _incFindingPeers () {
    if (++this._findingPeersCount !== 1) return

    for (const core of this._sessions) {
      this._findingPeers.push(core.findingPeers())
    }
  }

  _decFindingPeers () {
    if (--this._findingPeersCount !== 0) return

    while (this._findingPeers.length > 0) {
      this._findingPeers.pop()()
    }
  }

  async _openNamespaceFromBootstrap () {
    const ns = await this._bootstrap.getUserData(USERDATA_NAMESPACE_KEY)
    if (ns) {
      this._namespace = ns
    }
  }

  async _open () {
    if (this._root !== this) {
      await this._root.ready()
      if (!this.primaryKey) this.primaryKey = this._root.primaryKey
      if (this._bootstrap) await this._openNamespaceFromBootstrap()
      return
    }

    this._keyStorage = this.storage(PRIMARY_KEY_FILE_NAME)

    this.primaryKey = await new Promise((resolve, reject) => {
      this._keyStorage.stat((err, st) => {
        if (err && err.code !== 'ENOENT') return reject(err)
        if (err || st.size < 32 || this._overwrite) {
          const key = this.primaryKey || crypto.randomBytes(32)
          return this._keyStorage.write(0, key, err => {
            if (err) return reject(err)
            return resolve(key)
          })
        }
        this._keyStorage.read(0, 32, (err, key) => {
          if (err) return reject(err)
          if (this.primaryKey) return resolve(this.primaryKey)
          return resolve(key)
        })
      })
    })

    if (this._bootstrap) await this._openNamespaceFromBootstrap()
  }

  async _generateKeys (opts) {
    if (opts._discoveryKey) {
      return {
        manifest: null,
        keyPair: null,
        key: null,
        discoveryKey: opts._discoveryKey
      }
    }

    const keyPair = opts.name
      ? await this.createKeyPair(opts.name)
      : (opts.secretKey)
          ? { secretKey: opts.secretKey, publicKey: opts.publicKey }
          : null

    if (opts.manifest) {
      const key = Hypercore.key(opts.manifest)

      return {
        manifest: opts.manifest,
        keyPair,
        key,
        discoveryKey: crypto.discoveryKey(key)
      }
    }

    if (opts.key) {
      return {
        manifest: null,
        keyPair,
        key: opts.key,
        discoveryKey: crypto.discoveryKey(opts.key)
      }
    }

    const publicKey = opts.publicKey || keyPair.publicKey

    if (opts.compat === false) {
      const manifest = { signer: { publicKey } } // default manifest
      const key = Hypercore.key(manifest)

      return {
        manifest,
        keyPair,
        key,
        discoveryKey: crypto.discoveryKey(key)
      }
    }

    return {
      manifest: null,
      keyPair,
      key: publicKey,
      discoveryKey: crypto.discoveryKey(publicKey)
    }
  }

  _getPrereadyUserData (core, key) {
    // Need to manually read the header values before the Hypercore is ready, hence the ugliness.
    for (const { key: savedKey, value } of core.core.header.userData) {
      if (key === savedKey) return value
    }
    return null
  }

  async _preready (core) {
    const name = this._getPrereadyUserData(core, USERDATA_NAME_KEY)
    if (!name) return

    const namespace = this._getPrereadyUserData(core, USERDATA_NAMESPACE_KEY)
    const keyPair = await this.createKeyPair(b4a.toString(name), namespace)
    core.setKeyPair(keyPair)
  }

  _getLock (id) {
    let rw = this._locks.get(id)

    if (!rw) {
      rw = new RW()
      this._locks.set(id, rw)
    }

    return rw
  }

  async _preload (id, keys, opts) {
    const { manifest, keyPair, key } = keys

    while (this.cores.has(id)) {
      const existing = this.cores.get(id)
      if (existing.opened && !existing.closing) return { from: existing, keyPair, manifest, cache: !!opts.cache }
      if (existing.closing) {
        await existing.close()
      } else {
        await existing.ready().catch(safetyCatch)
      }
    }

    const hasKeyPair = !!(keyPair && keyPair.secretKey)
    const userData = {}
    if (opts.name) {
      userData[USERDATA_NAME_KEY] = b4a.from(opts.name)
      userData[USERDATA_NAMESPACE_KEY] = this._namespace
    }

    // No more async ticks allowed after this point -- necessary for caching

    const storageRoot = [CORES_DIR, id.slice(0, 2), id.slice(2, 4), id].join('/')
    const core = new Hypercore(p => this.storage(storageRoot + '/' + p), {
      _preready: this._preready.bind(this),
      notDownloadingLinger: this._notDownloadingLinger,
      autoClose: true,
      active: false,
      encryptionKey: opts.encryptionKey || null,
      isBlockKey: !!opts.isBlockKey,
      userData,
      manifest,
      key,
      compat: opts.compat,
      cache: opts.cache,
      createIfMissing: opts.createIfMissing === false ? false : !opts._discoveryKey,
      keyPair: hasKeyPair ? keyPair : null
    })

    if (this._root.closing) throw new Error('The corestore is closed')
    this.cores.set(id, core)
    core.ready().then(() => {
      if (core.closing) return // extra safety here as ready is a tick after open
      if (hasKeyPair) core.setKeyPair(keyPair)
      this._emitCore('core-open', core)

      const ondownloading = () => {
        for (const { stream } of this._replicationStreams) {
          core.replicate(stream, { session: true })
        }
      }
      // when the replicator says we are downloading, answer the call
      core.replicator.ondownloading = ondownloading
      // trigger once if the condition is already true
      if (core.replicator.downloading) ondownloading()
    }, () => {
      this.cores.delete(id)
    })
    core.once('close', () => {
      this._emitCore('core-close', core)
      this.cores.delete(id)
    })
    core.on('conflict', (len, fork, proof) => {
      this.emit('conflict', core, len, fork, proof)
    })

    return { from: core, keyPair, manifest, cache: !!opts.cache }
  }

  async createKeyPair (name, namespace = this._namespace) {
    if (!this.opened) await this.ready()

    const keyPair = {
      publicKey: b4a.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES),
      secretKey: b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
    }

    const seed = deriveSeed(this.primaryKey, namespace, name)
    sodium.crypto_sign_seed_keypair(keyPair.publicKey, keyPair.secretKey, seed)

    return keyPair
  }

  get (opts = {}) {
    if (this.closing || this._root.closing) throw new Error('The corestore is closed')
    opts = validateGetOptions(opts)

    if (opts.cache !== false) {
      opts.cache = opts.cache === true || (this.cache && !opts.cache) ? defaultCache() : opts.cache
    }
    if (this._readonly && opts.writable !== false) {
      opts.writable = false
    }

    let rw = null
    let id = null

    const core = new Hypercore(null, {
      ...opts,
      name: null,
      preload: async () => {
        if (opts.preload) opts = { ...opts, ...(await opts.preload()) }
        if (!this.opened) await this.ready()

        const keys = await this._generateKeys(opts)

        id = b4a.toString(keys.discoveryKey, 'hex')
        rw = (opts.exclusive && opts.writable !== false) ? this._getLock(id) : null

        if (rw) await rw.write.lock()
        return await this._preload(id, keys, opts)
      }
    })

    this._sessions.add(core)
    if (this._findingPeersCount > 0) {
      this._findingPeers.push(core.findingPeers())
    }

    const gc = () => {
      // technically better to also clear _findingPeers if we added it,
      // but the lifecycle for those are pretty short so prob not worth the complexity
      // as _decFindingPeers clear them all.
      this._sessions.delete(core)

      if (!rw) return
      rw.write.unlock()
      if (!rw.write.locked) this._locks.delete(id)
    }

    core.ready().catch(gc)
    core.once('close', gc)

    return core
  }

  replicate (isInitiator, opts) {
    const isExternal = isStream(isInitiator) || !!(opts && opts.stream)
    const stream = Hypercore.createProtocolStream(isInitiator, {
      ...opts,
      ondiscoverykey: async discoveryKey => {
        const core = this.get({ _discoveryKey: discoveryKey, active: false })

        try {
          await core.ready()
        } catch {
          return
        }

        // remote is asking for the core so we HAVE to answer even if not downloading
        if (!core.closing) core.replicate(stream, { session: true })
        await core.close()
      }
    })

    if (!this.passive) {
      for (const core of this.cores.values()) {
        // If the core is not opened, it will be replicated in preload.
        if (!core.opened || core.closing || !core.replicator.downloading) continue
        core.replicate(stream, { session: true })
      }
    }

    const streamRecord = { stream, isExternal }
    this._replicationStreams.push(streamRecord)

    stream.once('close', () => {
      this._replicationStreams.splice(this._replicationStreams.indexOf(streamRecord), 1)
    })

    return stream
  }

  namespace (name, opts) {
    if (name instanceof Hypercore) {
      return this.session({ ...opts, _bootstrap: name })
    }
    return this.session({ ...opts, namespace: generateNamespace(this._namespace, name) })
  }

  session (opts) {
    const session = new Corestore(this.storage, {
      namespace: this._namespace,
      cache: this.cache,
      writable: !this._readonly,
      _attached: opts && opts.detach === false ? this : null,
      _root: this._root,
      ...opts
    })
    if (this === this._root) this._rootStoreSessions.add(session)
    return session
  }

  _closeNamespace () {
    const closePromises = []
    for (const session of this._sessions) {
      closePromises.push(session.close())
    }
    return Promise.allSettled(closePromises)
  }

  async _closePrimaryNamespace () {
    const closePromises = []
    // At this point, the primary namespace is closing.
    for (const { stream, isExternal } of this._replicationStreams) {
      // Only close streams that were created by the Corestore
      if (!isExternal) stream.destroy()
    }
    for (const core of this.cores.values()) {
      closePromises.push(forceClose(core))
    }
    await Promise.allSettled(closePromises)
    await new Promise((resolve, reject) => {
      this._keyStorage.close(err => {
        if (err) return reject(err)
        return resolve(null)
      })
    })
  }

  async _close () {
    this._root._rootStoreSessions.delete(this)

    await this._closeNamespace()

    if (this._root === this) {
      await this._closePrimaryNamespace()
    } else if (this._attached) {
      await this._attached.close()
    }
  }
}

function validateGetOptions (opts) {
  const key = (b4a.isBuffer(opts) || typeof opts === 'string') ? hypercoreId.decode(opts) : null
  if (key) return { key }

  if (opts.key) {
    opts.key = hypercoreId.decode(opts.key)
  }
  if (opts.keyPair) {
    opts.publicKey = opts.keyPair.publicKey
    opts.secretKey = opts.keyPair.secretKey
  }

  if (opts.name && typeof opts.name !== 'string') throw new Error('name option must be a String')
  if (opts.name && opts.secretKey) throw new Error('Cannot provide both a name and a secret key')
  if (opts.publicKey && !b4a.isBuffer(opts.publicKey)) throw new Error('publicKey option must be a Buffer or Uint8Array')
  if (opts.secretKey && !b4a.isBuffer(opts.secretKey)) throw new Error('secretKey option must be a Buffer or Uint8Array')
  if (!opts._discoveryKey && (!opts.name && !opts.publicKey && !opts.manifest && !opts.key && !opts.preload)) throw new Error('Must provide either a name or a publicKey')
  return opts
}

function generateNamespace (namespace, name) {
  if (!b4a.isBuffer(name)) name = b4a.from(name)
  const out = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, [namespace, name])
  return out
}

function deriveSeed (primaryKey, namespace, name) {
  if (!b4a.isBuffer(name)) name = b4a.from(name)
  const out = b4a.alloc(32)
  sodium.crypto_generichash_batch(out, [NS, namespace, name], primaryKey)
  return out
}

function defaultCache () {
  return new Xache({ maxSize: 65536, maxAge: 0 })
}

function isStream (s) {
  return typeof s === 'object' && s && typeof s.pipe === 'function'
}

async function forceClose (core) {
  await core.ready()
  return Promise.all(core.sessions.map(s => s.close()))
}

},{"b4a":4,"hypercore":29,"hypercore-crypto":26,"hypercore-id-encoding":28,"read-write-mutexify":63,"ready-resource":64,"safety-catch":65,"sodium-universal":122,"xache":130}],20:[function(require,module,exports){
/**
 * The JavaScript implementation of CRC32 is a version of the slice-by-16 algorithm
 * as implemented by Stephan Brumme, see https://github.com/stbrumme/crc32.
 *
 * Copyright (c) 2011-2016 Stephan Brumme
 *
 * This software is provided 'as-is', without any express or implied warranty.
 * In no event will the authors be held liable for any damages arising from the
 * use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it freely,
 * subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not claim
 *    that you wrote the original software.
 *    If you use this software in a product, an acknowledgment in the product
 *    documentation would be appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 */

const lookup = require('./lookup')

exports.crc32 = function crc32 (buffer) {
  let crc = ~0
  let i = 0
  let length = buffer.byteLength

  while (length >= 16) {
    crc = lookup[15][buffer[i++] ^ (crc & 0xff)] ^
          lookup[14][buffer[i++] ^ ((crc >>> 8) & 0xff)] ^
          lookup[13][buffer[i++] ^ ((crc >>> 16) & 0xff)] ^
          lookup[12][buffer[i++] ^ (crc >>> 24)] ^
          lookup[11][buffer[i++]] ^
          lookup[10][buffer[i++]] ^
          lookup[9][buffer[i++]] ^
          lookup[8][buffer[i++]] ^
          lookup[7][buffer[i++]] ^
          lookup[6][buffer[i++]] ^
          lookup[5][buffer[i++]] ^
          lookup[4][buffer[i++]] ^
          lookup[3][buffer[i++]] ^
          lookup[2][buffer[i++]] ^
          lookup[1][buffer[i++]] ^
          lookup[0][buffer[i++]]

    length -= 16
  }

  while (length-- > 0) {
    crc = (crc >>> 8) ^ lookup[0][(crc & 0xff) ^ buffer[i++]]
  }

  return ~crc >>> 0
}

},{"./lookup":21}],21:[function(require,module,exports){
const lookup = new Array(16)

for (let i = 0; i < 16; i++) {
  lookup[i] = new Uint32Array(0x100)
}

for (let i = 0; i <= 0xff; i++) {
  let crc = i

  for (let j = 0; j < 8; j++) {
    crc = (crc >>> 1) ^ ((crc & 1) * 0xedb88320)
  }

  lookup[0][i] = crc
}

for (let i = 0; i <= 0xff; i++) {
  for (let j = 1; j < 16; j++) {
    lookup[j][i] = (lookup[j - 1][i] >>> 8) ^ lookup[0][lookup[j - 1][i] & 0xff]
  }
}

module.exports = lookup

},{}],22:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var R = typeof Reflect === 'object' ? Reflect : null
var ReflectApply = R && typeof R.apply === 'function'
  ? R.apply
  : function ReflectApply(target, receiver, args) {
    return Function.prototype.apply.call(target, receiver, args);
  }

var ReflectOwnKeys
if (R && typeof R.ownKeys === 'function') {
  ReflectOwnKeys = R.ownKeys
} else if (Object.getOwnPropertySymbols) {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target)
      .concat(Object.getOwnPropertySymbols(target));
  };
} else {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target);
  };
}

function ProcessEmitWarning(warning) {
  if (console && console.warn) console.warn(warning);
}

var NumberIsNaN = Number.isNaN || function NumberIsNaN(value) {
  return value !== value;
}

function EventEmitter() {
  EventEmitter.init.call(this);
}
module.exports = EventEmitter;
module.exports.once = once;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._eventsCount = 0;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
var defaultMaxListeners = 10;

function checkListener(listener) {
  if (typeof listener !== 'function') {
    throw new TypeError('The "listener" argument must be of type Function. Received type ' + typeof listener);
  }
}

Object.defineProperty(EventEmitter, 'defaultMaxListeners', {
  enumerable: true,
  get: function() {
    return defaultMaxListeners;
  },
  set: function(arg) {
    if (typeof arg !== 'number' || arg < 0 || NumberIsNaN(arg)) {
      throw new RangeError('The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' + arg + '.');
    }
    defaultMaxListeners = arg;
  }
});

EventEmitter.init = function() {

  if (this._events === undefined ||
      this._events === Object.getPrototypeOf(this)._events) {
    this._events = Object.create(null);
    this._eventsCount = 0;
  }

  this._maxListeners = this._maxListeners || undefined;
};

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function setMaxListeners(n) {
  if (typeof n !== 'number' || n < 0 || NumberIsNaN(n)) {
    throw new RangeError('The value of "n" is out of range. It must be a non-negative number. Received ' + n + '.');
  }
  this._maxListeners = n;
  return this;
};

function _getMaxListeners(that) {
  if (that._maxListeners === undefined)
    return EventEmitter.defaultMaxListeners;
  return that._maxListeners;
}

EventEmitter.prototype.getMaxListeners = function getMaxListeners() {
  return _getMaxListeners(this);
};

EventEmitter.prototype.emit = function emit(type) {
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  var doError = (type === 'error');

  var events = this._events;
  if (events !== undefined)
    doError = (doError && events.error === undefined);
  else if (!doError)
    return false;

  // If there is no 'error' event listener then throw.
  if (doError) {
    var er;
    if (args.length > 0)
      er = args[0];
    if (er instanceof Error) {
      // Note: The comments on the `throw` lines are intentional, they show
      // up in Node's output if this results in an unhandled exception.
      throw er; // Unhandled 'error' event
    }
    // At least give some kind of context to the user
    var err = new Error('Unhandled error.' + (er ? ' (' + er.message + ')' : ''));
    err.context = er;
    throw err; // Unhandled 'error' event
  }

  var handler = events[type];

  if (handler === undefined)
    return false;

  if (typeof handler === 'function') {
    ReflectApply(handler, this, args);
  } else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      ReflectApply(listeners[i], this, args);
  }

  return true;
};

function _addListener(target, type, listener, prepend) {
  var m;
  var events;
  var existing;

  checkListener(listener);

  events = target._events;
  if (events === undefined) {
    events = target._events = Object.create(null);
    target._eventsCount = 0;
  } else {
    // To avoid recursion in the case that type === "newListener"! Before
    // adding it to the listeners, first emit "newListener".
    if (events.newListener !== undefined) {
      target.emit('newListener', type,
                  listener.listener ? listener.listener : listener);

      // Re-assign `events` because a newListener handler could have caused the
      // this._events to be assigned to a new object
      events = target._events;
    }
    existing = events[type];
  }

  if (existing === undefined) {
    // Optimize the case of one listener. Don't need the extra array object.
    existing = events[type] = listener;
    ++target._eventsCount;
  } else {
    if (typeof existing === 'function') {
      // Adding the second element, need to change to array.
      existing = events[type] =
        prepend ? [listener, existing] : [existing, listener];
      // If we've already got an array, just append.
    } else if (prepend) {
      existing.unshift(listener);
    } else {
      existing.push(listener);
    }

    // Check for listener leak
    m = _getMaxListeners(target);
    if (m > 0 && existing.length > m && !existing.warned) {
      existing.warned = true;
      // No error code for this since it is a Warning
      // eslint-disable-next-line no-restricted-syntax
      var w = new Error('Possible EventEmitter memory leak detected. ' +
                          existing.length + ' ' + String(type) + ' listeners ' +
                          'added. Use emitter.setMaxListeners() to ' +
                          'increase limit');
      w.name = 'MaxListenersExceededWarning';
      w.emitter = target;
      w.type = type;
      w.count = existing.length;
      ProcessEmitWarning(w);
    }
  }

  return target;
}

EventEmitter.prototype.addListener = function addListener(type, listener) {
  return _addListener(this, type, listener, false);
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.prependListener =
    function prependListener(type, listener) {
      return _addListener(this, type, listener, true);
    };

function onceWrapper() {
  if (!this.fired) {
    this.target.removeListener(this.type, this.wrapFn);
    this.fired = true;
    if (arguments.length === 0)
      return this.listener.call(this.target);
    return this.listener.apply(this.target, arguments);
  }
}

function _onceWrap(target, type, listener) {
  var state = { fired: false, wrapFn: undefined, target: target, type: type, listener: listener };
  var wrapped = onceWrapper.bind(state);
  wrapped.listener = listener;
  state.wrapFn = wrapped;
  return wrapped;
}

EventEmitter.prototype.once = function once(type, listener) {
  checkListener(listener);
  this.on(type, _onceWrap(this, type, listener));
  return this;
};

EventEmitter.prototype.prependOnceListener =
    function prependOnceListener(type, listener) {
      checkListener(listener);
      this.prependListener(type, _onceWrap(this, type, listener));
      return this;
    };

// Emits a 'removeListener' event if and only if the listener was removed.
EventEmitter.prototype.removeListener =
    function removeListener(type, listener) {
      var list, events, position, i, originalListener;

      checkListener(listener);

      events = this._events;
      if (events === undefined)
        return this;

      list = events[type];
      if (list === undefined)
        return this;

      if (list === listener || list.listener === listener) {
        if (--this._eventsCount === 0)
          this._events = Object.create(null);
        else {
          delete events[type];
          if (events.removeListener)
            this.emit('removeListener', type, list.listener || listener);
        }
      } else if (typeof list !== 'function') {
        position = -1;

        for (i = list.length - 1; i >= 0; i--) {
          if (list[i] === listener || list[i].listener === listener) {
            originalListener = list[i].listener;
            position = i;
            break;
          }
        }

        if (position < 0)
          return this;

        if (position === 0)
          list.shift();
        else {
          spliceOne(list, position);
        }

        if (list.length === 1)
          events[type] = list[0];

        if (events.removeListener !== undefined)
          this.emit('removeListener', type, originalListener || listener);
      }

      return this;
    };

EventEmitter.prototype.off = EventEmitter.prototype.removeListener;

EventEmitter.prototype.removeAllListeners =
    function removeAllListeners(type) {
      var listeners, events, i;

      events = this._events;
      if (events === undefined)
        return this;

      // not listening for removeListener, no need to emit
      if (events.removeListener === undefined) {
        if (arguments.length === 0) {
          this._events = Object.create(null);
          this._eventsCount = 0;
        } else if (events[type] !== undefined) {
          if (--this._eventsCount === 0)
            this._events = Object.create(null);
          else
            delete events[type];
        }
        return this;
      }

      // emit removeListener for all listeners on all events
      if (arguments.length === 0) {
        var keys = Object.keys(events);
        var key;
        for (i = 0; i < keys.length; ++i) {
          key = keys[i];
          if (key === 'removeListener') continue;
          this.removeAllListeners(key);
        }
        this.removeAllListeners('removeListener');
        this._events = Object.create(null);
        this._eventsCount = 0;
        return this;
      }

      listeners = events[type];

      if (typeof listeners === 'function') {
        this.removeListener(type, listeners);
      } else if (listeners !== undefined) {
        // LIFO order
        for (i = listeners.length - 1; i >= 0; i--) {
          this.removeListener(type, listeners[i]);
        }
      }

      return this;
    };

function _listeners(target, type, unwrap) {
  var events = target._events;

  if (events === undefined)
    return [];

  var evlistener = events[type];
  if (evlistener === undefined)
    return [];

  if (typeof evlistener === 'function')
    return unwrap ? [evlistener.listener || evlistener] : [evlistener];

  return unwrap ?
    unwrapListeners(evlistener) : arrayClone(evlistener, evlistener.length);
}

EventEmitter.prototype.listeners = function listeners(type) {
  return _listeners(this, type, true);
};

EventEmitter.prototype.rawListeners = function rawListeners(type) {
  return _listeners(this, type, false);
};

EventEmitter.listenerCount = function(emitter, type) {
  if (typeof emitter.listenerCount === 'function') {
    return emitter.listenerCount(type);
  } else {
    return listenerCount.call(emitter, type);
  }
};

EventEmitter.prototype.listenerCount = listenerCount;
function listenerCount(type) {
  var events = this._events;

  if (events !== undefined) {
    var evlistener = events[type];

    if (typeof evlistener === 'function') {
      return 1;
    } else if (evlistener !== undefined) {
      return evlistener.length;
    }
  }

  return 0;
}

EventEmitter.prototype.eventNames = function eventNames() {
  return this._eventsCount > 0 ? ReflectOwnKeys(this._events) : [];
};

function arrayClone(arr, n) {
  var copy = new Array(n);
  for (var i = 0; i < n; ++i)
    copy[i] = arr[i];
  return copy;
}

function spliceOne(list, index) {
  for (; index + 1 < list.length; index++)
    list[index] = list[index + 1];
  list.pop();
}

function unwrapListeners(arr) {
  var ret = new Array(arr.length);
  for (var i = 0; i < ret.length; ++i) {
    ret[i] = arr[i].listener || arr[i];
  }
  return ret;
}

function once(emitter, name) {
  return new Promise(function (resolve, reject) {
    function errorListener(err) {
      emitter.removeListener(name, resolver);
      reject(err);
    }

    function resolver() {
      if (typeof emitter.removeListener === 'function') {
        emitter.removeListener('error', errorListener);
      }
      resolve([].slice.call(arguments));
    };

    eventTargetAgnosticAddListener(emitter, name, resolver, { once: true });
    if (name !== 'error') {
      addErrorHandlerIfEventEmitter(emitter, errorListener, { once: true });
    }
  });
}

function addErrorHandlerIfEventEmitter(emitter, handler, flags) {
  if (typeof emitter.on === 'function') {
    eventTargetAgnosticAddListener(emitter, 'error', handler, flags);
  }
}

function eventTargetAgnosticAddListener(emitter, name, listener, flags) {
  if (typeof emitter.on === 'function') {
    if (flags.once) {
      emitter.once(name, listener);
    } else {
      emitter.on(name, listener);
    }
  } else if (typeof emitter.addEventListener === 'function') {
    // EventTarget does not have `error` event semantics like Node
    // EventEmitters, we do not listen for `error` events here.
    emitter.addEventListener(name, function wrapListener(arg) {
      // IE does not have builtin `{ once: true }` support so we
      // have to do it manually.
      if (flags.once) {
        emitter.removeEventListener(name, wrapListener);
      }
      listener(arg);
    });
  } else {
    throw new TypeError('The "emitter" argument must be of type EventEmitter. Received type ' + typeof emitter);
  }
}

},{}],23:[function(require,module,exports){
module.exports = class FixedFIFO {
  constructor (hwm) {
    if (!(hwm > 0) || ((hwm - 1) & hwm) !== 0) throw new Error('Max size for a FixedFIFO should be a power of two')
    this.buffer = new Array(hwm)
    this.mask = hwm - 1
    this.top = 0
    this.btm = 0
    this.next = null
  }

  clear () {
    this.top = this.btm = 0
    this.next = null
    this.buffer.fill(undefined)
  }

  push (data) {
    if (this.buffer[this.top] !== undefined) return false
    this.buffer[this.top] = data
    this.top = (this.top + 1) & this.mask
    return true
  }

  shift () {
    const last = this.buffer[this.btm]
    if (last === undefined) return undefined
    this.buffer[this.btm] = undefined
    this.btm = (this.btm + 1) & this.mask
    return last
  }

  peek () {
    return this.buffer[this.btm]
  }

  isEmpty () {
    return this.buffer[this.btm] === undefined
  }
}

},{}],24:[function(require,module,exports){
const FixedFIFO = require('./fixed-size')

module.exports = class FastFIFO {
  constructor (hwm) {
    this.hwm = hwm || 16
    this.head = new FixedFIFO(this.hwm)
    this.tail = this.head
    this.length = 0
  }

  clear () {
    this.head = this.tail
    this.head.clear()
    this.length = 0
  }

  push (val) {
    this.length++
    if (!this.head.push(val)) {
      const prev = this.head
      this.head = prev.next = new FixedFIFO(2 * this.head.buffer.length)
      this.head.push(val)
    }
  }

  shift () {
    if (this.length !== 0) this.length--
    const val = this.tail.shift()
    if (val === undefined && this.tail.next) {
      const next = this.tail.next
      this.tail.next = null
      this.tail = next
      return this.tail.shift()
    }

    return val
  }

  peek () {
    const val = this.tail.peek()
    if (val === undefined && this.tail.next) return this.tail.next.peek()
    return val
  }

  isEmpty () {
    return this.length === 0
  }
}

},{"./fixed-size":23}],25:[function(require,module,exports){
exports.fullRoots = function (index, result) {
  if (index & 1) throw new Error('You can only look up roots for depth(0) blocks')
  if (!result) result = []

  index /= 2

  let offset = 0
  let factor = 1

  while (true) {
    if (!index) return result
    while (factor * 2 <= index) factor *= 2
    result.push(offset + factor - 1)
    offset = offset + 2 * factor
    index -= factor
    factor = 1
  }
}

exports.futureRoots = function (index, result) {
  if (index & 1) throw new Error('You can only look up future roots for depth(0) blocks')
  if (!result) result = []

  let factor = 1

  // make first root
  while (factor * 2 <= index) factor *= 2

  // full factor of 2 - done
  if (factor * 2 - 2 === index) return result

  let pos = factor / 2 - 1

  // while its not a full tree
  while ((pos + factor / 2 - 1) !== index) {
    pos += factor

    // read too far, to to left child
    while ((pos + factor / 2 - 1) > index) {
      factor /= 2
      pos -= factor / 2
    }

    // the "gap" is a future root
    result.push(pos - factor / 2)
  }

  return result
}

exports.depth = function (index) {
  let depth = 0

  index += 1
  while (!(index & 1)) {
    depth++
    index = rightShift(index)
  }

  return depth
}

exports.sibling = function (index, depth) {
  if (!depth) depth = exports.depth(index)
  const offset = exports.offset(index, depth)

  return exports.index(depth, offset & 1 ? offset - 1 : offset + 1)
}

exports.parent = function (index, depth) {
  if (!depth) depth = exports.depth(index)
  const offset = exports.offset(index, depth)

  return exports.index(depth + 1, rightShift(offset))
}

exports.leftChild = function (index, depth) {
  if (!(index & 1)) return -1
  if (!depth) depth = exports.depth(index)
  return exports.index(depth - 1, exports.offset(index, depth) * 2)
}

exports.rightChild = function (index, depth) {
  if (!(index & 1)) return -1
  if (!depth) depth = exports.depth(index)
  return exports.index(depth - 1, 1 + (exports.offset(index, depth) * 2))
}

exports.children = function (index, depth) {
  if (!(index & 1)) return null

  if (!depth) depth = exports.depth(index)
  const offset = exports.offset(index, depth) * 2

  return [
    exports.index(depth - 1, offset),
    exports.index(depth - 1, offset + 1)
  ]
}

exports.leftSpan = function (index, depth) {
  if (!(index & 1)) return index
  if (!depth) depth = exports.depth(index)
  return exports.offset(index, depth) * twoPow(depth + 1)
}

exports.rightSpan = function (index, depth) {
  if (!(index & 1)) return index
  if (!depth) depth = exports.depth(index)
  return (exports.offset(index, depth) + 1) * twoPow(depth + 1) - 2
}

exports.count = function (index, depth) {
  if (!(index & 1)) return 1
  if (!depth) depth = exports.depth(index)
  return twoPow(depth + 1) - 1
}

exports.countLeaves = function (index) {
  return (exports.count(index) + 1) / 2
}

exports.spans = function (index, depth) {
  if (!(index & 1)) return [index, index]
  if (!depth) depth = exports.depth(index)

  const offset = exports.offset(index, depth)
  const width = twoPow(depth + 1)

  return [offset * width, (offset + 1) * width - 2]
}

exports.index = function (depth, offset) {
  return (1 + 2 * offset) * twoPow(depth) - 1
}

exports.offset = function (index, depth) {
  if (!(index & 1)) return index / 2
  if (!depth) depth = exports.depth(index)

  return ((index + 1) / twoPow(depth) - 1) / 2
}

exports.iterator = function (index) {
  const ite = new Iterator()
  ite.seek(index || 0)
  return ite
}

function twoPow (n) {
  return n < 31 ? 1 << n : ((1 << 30) * (1 << (n - 30)))
}

function rightShift (n) {
  return (n - (n & 1)) / 2
}

function Iterator () {
  this.index = 0
  this.offset = 0
  this.factor = 0
}

Iterator.prototype.seek = function (index) {
  this.index = index
  if (this.index & 1) {
    this.offset = exports.offset(index)
    this.factor = twoPow(exports.depth(index) + 1)
  } else {
    this.offset = index / 2
    this.factor = 2
  }
}

Iterator.prototype.isLeft = function () {
  return (this.offset & 1) === 0
}

Iterator.prototype.isRight = function () {
  return (this.offset & 1) === 1
}

Iterator.prototype.contains = function (index) {
  return index > this.index
    ? index < (this.index + this.factor / 2)
    : index < this.index
      ? index > (this.index - this.factor / 2)
      : true
}

Iterator.prototype.prev = function () {
  if (!this.offset) return this.index
  this.offset--
  this.index -= this.factor
  return this.index
}

Iterator.prototype.next = function () {
  this.offset++
  this.index += this.factor
  return this.index
}

Iterator.prototype.count = function () {
  if (!(this.index & 1)) return 1
  return this.factor - 1
}

Iterator.prototype.countLeaves = function () {
  return (this.count() + 1) / 2
}

Iterator.prototype.sibling = function () {
  return this.isLeft() ? this.next() : this.prev()
}

Iterator.prototype.parent = function () {
  if (this.offset & 1) {
    this.index -= this.factor / 2
    this.offset = (this.offset - 1) / 2
  } else {
    this.index += this.factor / 2
    this.offset /= 2
  }
  this.factor *= 2
  return this.index
}

Iterator.prototype.leftSpan = function () {
  this.index = this.index - this.factor / 2 + 1
  this.offset = this.index / 2
  this.factor = 2
  return this.index
}

Iterator.prototype.rightSpan = function () {
  this.index = this.index + this.factor / 2 - 1
  this.offset = this.index / 2
  this.factor = 2
  return this.index
}

Iterator.prototype.leftChild = function () {
  if (this.factor === 2) return this.index
  this.factor /= 2
  this.index -= this.factor / 2
  this.offset *= 2
  return this.index
}

Iterator.prototype.rightChild = function () {
  if (this.factor === 2) return this.index
  this.factor /= 2
  this.index += this.factor / 2
  this.offset = 2 * this.offset + 1
  return this.index
}

Iterator.prototype.nextTree = function () {
  this.index = this.index + this.factor / 2 + 1
  this.offset = this.index / 2
  this.factor = 2
  return this.index
}

Iterator.prototype.prevTree = function () {
  if (!this.offset) {
    this.index = 0
    this.factor = 2
  } else {
    this.index = this.index - this.factor / 2 - 1
    this.offset = this.index / 2
    this.factor = 2
  }
  return this.index
}

Iterator.prototype.fullRoot = function (index) {
  if (index <= this.index || (this.index & 1) > 0) return false
  while (index > this.index + this.factor + this.factor / 2) {
    this.index += this.factor / 2
    this.factor *= 2
    this.offset /= 2
  }
  return true
}

},{}],26:[function(require,module,exports){
const sodium = require('sodium-universal')
const c = require('compact-encoding')
const b4a = require('b4a')

// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
const LEAF_TYPE = b4a.from([0])
const PARENT_TYPE = b4a.from([1])
const ROOT_TYPE = b4a.from([2])

const HYPERCORE = b4a.from('hypercore')

exports.keyPair = function (seed) {
  const publicKey = b4a.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.allocUnsafe(sodium.crypto_sign_SECRETKEYBYTES)

  if (seed) sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  else sodium.crypto_sign_keypair(publicKey, secretKey)

  return {
    publicKey,
    secretKey
  }
}

exports.validateKeyPair = function (keyPair) {
  const pk = b4a.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
  sodium.crypto_sign_ed25519_sk_to_pk(pk, keyPair.secretKey)
  return b4a.equals(pk, keyPair.publicKey)
}

exports.sign = function (message, secretKey) {
  const signature = b4a.allocUnsafe(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, message, secretKey)
  return signature
}

exports.verify = function (message, signature, publicKey) {
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}

exports.data = function (data) {
  const out = b4a.allocUnsafe(32)

  sodium.crypto_generichash_batch(out, [
    LEAF_TYPE,
    c.encode(c.uint64, data.byteLength),
    data
  ])

  return out
}

exports.parent = function (a, b) {
  if (a.index > b.index) {
    const tmp = a
    a = b
    b = tmp
  }

  const out = b4a.allocUnsafe(32)

  sodium.crypto_generichash_batch(out, [
    PARENT_TYPE,
    c.encode(c.uint64, a.size + b.size),
    a.hash,
    b.hash
  ])

  return out
}

exports.tree = function (roots, out) {
  const buffers = new Array(3 * roots.length + 1)
  let j = 0

  buffers[j++] = ROOT_TYPE

  for (let i = 0; i < roots.length; i++) {
    const r = roots[i]
    buffers[j++] = r.hash
    buffers[j++] = c.encode(c.uint64, r.index)
    buffers[j++] = c.encode(c.uint64, r.size)
  }

  if (!out) out = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, buffers)
  return out
}

exports.hash = function (data, out) {
  if (!out) out = b4a.allocUnsafe(32)
  if (!Array.isArray(data)) data = [data]

  sodium.crypto_generichash_batch(out, data)

  return out
}

exports.randomBytes = function (n) {
  const buf = b4a.allocUnsafe(n)
  sodium.randombytes_buf(buf)
  return buf
}

exports.discoveryKey = function (publicKey) {
  const digest = b4a.allocUnsafe(32)
  sodium.crypto_generichash(digest, HYPERCORE, publicKey)
  return digest
}

if (sodium.sodium_free) {
  exports.free = function (secureBuf) {
    if (secureBuf.secure) sodium.sodium_free(secureBuf)
  }
} else {
  exports.free = function () {}
}

exports.namespace = function (name, count) {
  const ids = typeof count === 'number' ? range(count) : count
  const buf = b4a.allocUnsafe(32 * ids.length)
  const list = new Array(ids.length)

  const ns = b4a.allocUnsafe(33)
  sodium.crypto_generichash(ns.subarray(0, 32), typeof name === 'string' ? b4a.from(name) : name)

  for (let i = 0; i < list.length; i++) {
    list[i] = buf.subarray(32 * i, 32 * i + 32)
    ns[32] = ids[i]
    sodium.crypto_generichash(list[i], ns)
  }

  return list
}

function range (count) {
  const arr = new Array(count)
  for (let i = 0; i < count; i++) arr[i] = i
  return arr
}

},{"b4a":4,"compact-encoding":16,"sodium-universal":122}],27:[function(require,module,exports){
module.exports = class HypercoreError extends Error {
  constructor (msg, code, fn = HypercoreError) {
    super(`${code}: ${msg}`)
    this.code = code

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, fn)
    }
  }

  get name () {
    return 'HypercoreError'
  }

  static BAD_ARGUMENT (msg) {
    return new HypercoreError(msg, 'BAD_ARGUMENT', HypercoreError.BAD_ARGUMENT)
  }

  static STORAGE_EMPTY (msg) {
    return new HypercoreError(msg, 'STORAGE_EMPTY', HypercoreError.STORAGE_EMPTY)
  }

  static STORAGE_CONFLICT (msg) {
    return new HypercoreError(msg, 'STORAGE_CONFLICT', HypercoreError.STORAGE_CONFLICT)
  }

  static INVALID_SIGNATURE (msg) {
    return new HypercoreError(msg, 'INVALID_SIGNATURE', HypercoreError.INVALID_SIGNATURE)
  }

  static INVALID_CAPABILITY (msg) {
    return new HypercoreError(msg, 'INVALID_CAPABILITY', HypercoreError.INVALID_CAPABILITY)
  }

  static INVALID_CHECKSUM (msg = 'Invalid checksum') {
    return new HypercoreError(msg, 'INVALID_CHECKSUM', HypercoreError.INVALID_CHECKSUM)
  }

  static INVALID_OPERATION (msg) {
    return new HypercoreError(msg, 'INVALID_OPERATION', HypercoreError.INVALID_OPERATION)
  }

  static INVALID_PROOF (msg = 'Proof not verifiable') {
    return new HypercoreError(msg, 'INVALID_PROOF', HypercoreError.INVALID_PROOF)
  }

  static BLOCK_NOT_AVAILABLE (msg = 'Block is not available') {
    return new HypercoreError(msg, 'BLOCK_NOT_AVAILABLE', HypercoreError.BLOCK_NOT_AVAILABLE)
  }

  static SNAPSHOT_NOT_AVAILABLE (msg = 'Snapshot is not available') {
    return new HypercoreError(msg, 'SNAPSHOT_NOT_AVAILABLE', HypercoreError.SNAPSHOT_NOT_AVAILABLE)
  }

  static REQUEST_CANCELLED (msg = 'Request was cancelled') {
    return new HypercoreError(msg, 'REQUEST_CANCELLED', HypercoreError.REQUEST_CANCELLED)
  }

  static REQUEST_TIMEOUT (msg = 'Request timed out') {
    return new HypercoreError(msg, 'REQUEST_TIMEOUT', HypercoreError.REQUEST_TIMEOUT)
  }

  static SESSION_NOT_WRITABLE (msg = 'Session is not writable') {
    return new HypercoreError(msg, 'SESSION_NOT_WRITABLE', HypercoreError.SESSION_NOT_WRITABLE)
  }

  static SESSION_CLOSED (msg = 'Session is closed') {
    return new HypercoreError(msg, 'SESSION_CLOSED', HypercoreError.SESSION_CLOSED)
  }

  static BATCH_UNFLUSHED (msg = 'Batch not yet flushed') {
    return new HypercoreError(msg, 'BATCH_UNFLUSHED', HypercoreError.BATCH_UNFLUSHED)
  }

  static BATCH_ALREADY_EXISTS (msg = 'Batch already exists') {
    return new HypercoreError(msg, 'BATCH_ALREADY_EXISTS', HypercoreError.BATCH_ALREADY_EXISTS)
  }

  static BATCH_ALREADY_FLUSHED (msg = 'Batch has already been flushed') {
    return new HypercoreError(msg, 'BATCH_ALREADY_FLUSHED', HypercoreError.BATCH_ALREADY_FLUSHED)
  }

  static OPLOG_CORRUPT (msg = 'Oplog file appears corrupt or out of date') {
    return new HypercoreError(msg, 'OPLOG_CORRUPT', HypercoreError.OPLOG_CORRUPT)
  }

  static OPLOG_HEADER_OVERFLOW (msg = 'Oplog header exceeds page size') {
    return new HypercoreError(msg, 'OPLOG_HEADER_OVERFLOW', HypercoreError.OPLOG_HEADER_OVERFLOW)
  }

  static INVALID_OPLOG_VERSION (msg = 'Invalid header version') {
    return new HypercoreError(msg, 'INVALID_OPLOG_VERSION', HypercoreError.INVALID_OPLOG_VERSION)
  }
}

},{}],28:[function(require,module,exports){
const z32 = require('z32')
const b4a = require('b4a')

module.exports = {
  encode,
  decode,
  normalize,
  isValid
}

function encode (key) {
  if (!b4a.isBuffer(key)) throw new Error('Key must be a Buffer')
  if (key.byteLength !== 32) throw new Error('Key must be 32-bytes long')
  return z32.encode(key)
}

function decode (id) {
  if (b4a.isBuffer(id)) {
    if (id.byteLength !== 32) throw new Error('ID must be 32-bytes long')
    return id
  }
  if (typeof id === 'string') {
    if (id.length === 52) return z32.decode(id)
    if (id.length === 64) {
      const buf = b4a.from(id, 'hex')
      if (buf.byteLength === 32) return buf
    }
  }
  throw new Error('Invalid Hypercore key')
}

function normalize (any) {
  return encode(decode(any))
}

function isValid (any) {
  try {
    decode(any)
    return true
  } catch {
    return false
  }
}

},{"b4a":4,"z32":133}],29:[function(require,module,exports){
const { EventEmitter } = require('events')
const RAF = require('random-access-file')
const isOptions = require('is-options')
const hypercoreCrypto = require('hypercore-crypto')
const c = require('compact-encoding')
const b4a = require('b4a')
const Xache = require('xache')
const NoiseSecretStream = require('@hyperswarm/secret-stream')
const Protomux = require('protomux')
const z32 = require('z32')
const id = require('hypercore-id-encoding')

const Replicator = require('./lib/replicator')
const Core = require('./lib/core')
const BlockEncryption = require('./lib/block-encryption')
const Info = require('./lib/info')
const Download = require('./lib/download')
const Batch = require('./lib/batch')
const { manifestHash, defaultSignerManifest, createVerifier, createManifest, isCompat } = require('./lib/manifest')
const { ReadStream, WriteStream, ByteStream } = require('./lib/streams')
const {
  BAD_ARGUMENT,
  SESSION_CLOSED,
  SESSION_NOT_WRITABLE,
  SNAPSHOT_NOT_AVAILABLE
} = require('hypercore-errors')

const promises = Symbol.for('hypercore.promises')
const inspect = Symbol.for('nodejs.util.inspect.custom')

module.exports = class Hypercore extends EventEmitter {
  constructor (storage, key, opts) {
    super()

    if (isOptions(storage)) {
      opts = storage
      storage = null
      key = opts.key || null
    } else if (isOptions(key)) {
      opts = key
      key = opts.key || null
    }

    if (key && typeof key === 'string') key = id.decode(key)
    if (!opts) opts = {}

    if (!storage) storage = opts.storage

    this[promises] = true

    this.storage = null
    this.crypto = opts.crypto || hypercoreCrypto
    this.core = null
    this.replicator = null
    this.encryption = null
    this.extensions = new Map()
    this.cache = createCache(opts.cache)

    this.valueEncoding = null
    this.encodeBatch = null
    this.activeRequests = []

    this.id = null
    this.key = key || null
    this.keyPair = opts.keyPair || null
    this.readable = true
    this.writable = false
    this.opened = false
    this.closed = false
    this.snapshotted = !!opts.snapshot
    this.sparse = opts.sparse !== false
    this.sessions = opts._sessions || [this]
    this.autoClose = !!opts.autoClose
    this.onwait = opts.onwait || null
    this.wait = opts.wait !== false
    this.timeout = opts.timeout || 0
    this.closing = null
    this.opening = null

    this._clone = opts.clone || null
    this._readonly = opts.writable === false
    this._preappend = preappend.bind(this)
    this._snapshot = null
    this._findingPeers = 0
    this._active = opts.active !== false

    this.opening = this._openSession(key, storage, opts)
    this.opening.catch(noop)
  }

  [inspect] (depth, opts) {
    let indent = ''
    if (typeof opts.indentationLvl === 'number') {
      while (indent.length < opts.indentationLvl) indent += ' '
    }

    let peers = ''
    const min = Math.min(this.peers.length, 5)

    for (let i = 0; i < min; i++) {
      const peer = this.peers[i]

      peers += indent + '    Peer(\n'
      peers += indent + '      remotePublicKey: ' + opts.stylize(toHex(peer.remotePublicKey), 'string') + '\n'
      peers += indent + '      remoteLength: ' + opts.stylize(peer.remoteLength, 'number') + '\n'
      peers += indent + '      remoteFork: ' + opts.stylize(peer.remoteFork, 'number') + '\n'
      peers += indent + '      remoteCanUpgrade: ' + opts.stylize(peer.remoteCanUpgrade, 'boolean') + '\n'
      peers += indent + '    )' + '\n'
    }

    if (this.peers.length > 5) {
      peers += indent + '  ... and ' + (this.peers.length - 5) + ' more\n'
    }

    if (peers) peers = '[\n' + peers + indent + '  ]'
    else peers = '[ ' + opts.stylize(0, 'number') + ' ]'

    return this.constructor.name + '(\n' +
      indent + '  id: ' + opts.stylize(this.id, 'string') + '\n' +
      indent + '  key: ' + opts.stylize(toHex(this.key), 'string') + '\n' +
      indent + '  discoveryKey: ' + opts.stylize(toHex(this.discoveryKey), 'string') + '\n' +
      indent + '  opened: ' + opts.stylize(this.opened, 'boolean') + '\n' +
      indent + '  closed: ' + opts.stylize(this.closed, 'boolean') + '\n' +
      indent + '  snapshotted: ' + opts.stylize(this.snapshotted, 'boolean') + '\n' +
      indent + '  sparse: ' + opts.stylize(this.sparse, 'boolean') + '\n' +
      indent + '  writable: ' + opts.stylize(this.writable, 'boolean') + '\n' +
      indent + '  length: ' + opts.stylize(this.length, 'number') + '\n' +
      indent + '  fork: ' + opts.stylize(this.fork, 'number') + '\n' +
      indent + '  sessions: [ ' + opts.stylize(this.sessions.length, 'number') + ' ]\n' +
      indent + '  activeRequests: [ ' + opts.stylize(this.activeRequests.length, 'number') + ' ]\n' +
      indent + '  peers: ' + peers + '\n' +
      indent + ')'
  }

  static key (manifest, { compat } = {}) {
    return compat ? manifest.signer.publicKey : manifestHash(createManifest(manifest))
  }

  static discoveryKey (key) {
    return hypercoreCrypto.discoveryKey(key)
  }

  static getProtocolMuxer (stream) {
    return stream.noiseStream.userData
  }

  static createProtocolStream (isInitiator, opts = {}) {
    let outerStream = Protomux.isProtomux(isInitiator)
      ? isInitiator.stream
      : isStream(isInitiator)
        ? isInitiator
        : opts.stream

    let noiseStream = null

    if (outerStream) {
      noiseStream = outerStream.noiseStream
    } else {
      noiseStream = new NoiseSecretStream(isInitiator, null, opts)
      outerStream = noiseStream.rawStream
    }
    if (!noiseStream) throw BAD_ARGUMENT('Invalid stream')

    if (!noiseStream.userData) {
      const protocol = Protomux.from(noiseStream)

      if (opts.keepAlive !== false) {
        noiseStream.setKeepAlive(5000)
      }
      noiseStream.userData = protocol
    }

    if (opts.ondiscoverykey) {
      noiseStream.userData.pair({ protocol: 'hypercore/alpha' }, opts.ondiscoverykey)
    }

    return outerStream
  }

  static defaultStorage (storage, opts = {}) {
    if (typeof storage !== 'string') {
      if (!isRandomAccessClass(storage)) return storage
      const Cls = storage // just to satisfy standard...
      return name => new Cls(name)
    }

    const directory = storage
    const toLock = opts.unlocked ? null : (opts.lock || 'oplog')
    const pool = opts.pool || (opts.poolSize ? RAF.createPool(opts.poolSize) : null)
    const rmdir = !!opts.rmdir
    const writable = opts.writable !== false

    return createFile

    function createFile (name) {
      const lock = toLock === null ? false : isFile(name, toLock)
      const sparse = isFile(name, 'data') || isFile(name, 'bitfield') || isFile(name, 'tree')
      return new RAF(name, { directory, lock, sparse, pool: lock ? null : pool, rmdir, writable })
    }

    function isFile (name, n) {
      return name === n || name.endsWith('/' + n)
    }
  }

  snapshot (opts) {
    return this.session({ ...opts, snapshot: true })
  }

  session (opts = {}) {
    if (this.closing) {
      // This makes the closing logic a lot easier. If this turns out to be a problem
      // in practice, open an issue and we'll try to make a solution for it.
      throw SESSION_CLOSED('Cannot make sessions on a closing core')
    }

    const sparse = opts.sparse === false ? false : this.sparse
    const wait = opts.wait === false ? false : this.wait
    const writable = opts.writable === false ? false : !this._readonly
    const onwait = opts.onwait === undefined ? this.onwait : opts.onwait
    const timeout = opts.timeout === undefined ? this.timeout : opts.timeout
    const Clz = opts.class || Hypercore
    const s = new Clz(this.storage, this.key, {
      ...opts,
      sparse,
      wait,
      onwait,
      timeout,
      writable,
      _opening: this.opening,
      _sessions: this.sessions
    })

    s._passCapabilities(this)

    // Configure the cache unless explicitly disabled.
    if (opts.cache !== false) {
      s.cache = opts.cache === true || !opts.cache ? this.cache : opts.cache
    }

    if (this.opened) ensureEncryption(s, opts)

    this.sessions.push(s)

    return s
  }

  async setEncryptionKey (encryptionKey, opts) {
    if (!this.opened) await this.opening
    this.encryption = encryptionKey ? new BlockEncryption(encryptionKey, this.key, { compat: this.core.compat, ...opts }) : null
  }

  setKeyPair (keyPair) {
    this.keyPair = keyPair
    this.writable = this._isWritable()
  }

  _passCapabilities (o) {
    if (!this.keyPair) this.keyPair = o.keyPair
    this.crypto = o.crypto
    this.id = o.id
    this.key = o.key
    this.core = o.core
    this.replicator = o.replicator
    this.encryption = o.encryption
    this.writable = this._isWritable()
    this.autoClose = o.autoClose

    if (this.snapshotted && this.core && !this._snapshot) this._updateSnapshot()
  }

  async _openFromExisting (from, opts) {
    if (!from.opened) await from.opening

    // includes ourself as well, so the loop below also updates us
    const sessions = this.sessions

    for (const s of sessions) {
      s.sessions = from.sessions
      s.sessions.push(s)
      s._passCapabilities(from)
    }

    this.storage = from.storage
    this.replicator.findingPeers += this._findingPeers

    ensureEncryption(this, opts)

    // we need to manually fwd the encryption cap as the above removes it potentially
    if (this.encryption && !from.encryption) {
      for (const s of sessions) s.encryption = this.encryption
    }
  }

  async _openSession (key, storage, opts) {
    const isFirst = !opts._opening

    if (!isFirst) await opts._opening
    if (opts.preload) opts = { ...opts, ...(await this._retryPreload(opts.preload)) }
    if (this.cache === null && opts.cache) this.cache = createCache(opts.cache)

    if (isFirst) {
      await this._openCapabilities(key, storage, opts)

      // check we are the actual root and not a opts.from session
      if (!opts.from) {
        // Only the root session should pass capabilities to other sessions.
        for (let i = 0; i < this.sessions.length; i++) {
          const s = this.sessions[i]
          if (s !== this) s._passCapabilities(this)
        }

        // copy state over
        if (this._clone) {
          const { from, signature } = this._clone
          await from.opening
          await this.core.copyFrom(from.core, signature)
          this._clone = null
        }
      }
    } else {
      ensureEncryption(this, opts)
    }

    this.writable = this._isWritable()

    if (opts.valueEncoding) {
      this.valueEncoding = c.from(opts.valueEncoding)
    }
    if (opts.encodeBatch) {
      this.encodeBatch = opts.encodeBatch
    }

    // Start continous replication if not in sparse mode.
    if (!this.sparse) this.download({ start: 0, end: -1 })

    // This is a hidden option that's only used by Corestore.
    // It's required so that corestore can load a name from userData before 'ready' is emitted.
    if (opts._preready) await opts._preready(this)

    this.replicator.updateActivity(this._active ? 1 : 0, this)

    this.opened = true
    this.emit('ready')
  }

  async _retryPreload (preload) {
    while (true) { // TODO: better long term fix is allowing lib/core.js creation from the outside...
      const result = await preload()
      const from = result && result.from
      if (from) {
        if (!from.opened) await from.ready()
        if (from.closing) continue
      }
      return result
    }
  }

  async _openCapabilities (key, storage, opts) {
    if (opts.from) return this._openFromExisting(opts.from, opts)

    const unlocked = !!opts.unlocked
    this.storage = Hypercore.defaultStorage(opts.storage || storage, { unlocked, writable: !unlocked })

    this.core = await Core.open(this.storage, {
      compat: opts.compat,
      force: opts.force,
      createIfMissing: opts.createIfMissing,
      readonly: unlocked,
      overwrite: opts.overwrite,
      key,
      keyPair: opts.keyPair,
      crypto: this.crypto,
      legacy: opts.legacy,
      manifest: opts.manifest,
      onupdate: this._oncoreupdate.bind(this),
      onconflict: this._oncoreconflict.bind(this)
    })

    if (opts.userData) {
      for (const [key, value] of Object.entries(opts.userData)) {
        await this.core.userData(key, value)
      }
    }

    this.key = this.core.header.key
    this.keyPair = this.core.header.keyPair
    this.id = z32.encode(this.key)

    this.replicator = new Replicator(this.core, this.key, {
      eagerUpgrade: true,
      notDownloadingLinger: opts.notDownloadingLinger,
      allowFork: opts.allowFork !== false,
      onpeerupdate: this._onpeerupdate.bind(this),
      onupload: this._onupload.bind(this),
      oninvalid: this._oninvalid.bind(this)
    })

    this.replicator.findingPeers += this._findingPeers

    if (!this.encryption && opts.encryptionKey) {
      this.encryption = new BlockEncryption(opts.encryptionKey, this.key, { compat: this.core.compat, isBlockKey: opts.isBlockKey })
    }
  }

  _getSnapshot () {
    if (this.sparse) {
      return {
        length: this.core.tree.length,
        byteLength: this.core.tree.byteLength,
        fork: this.core.tree.fork,
        compatLength: this.core.tree.length
      }
    }

    return {
      length: this.core.header.hints.contiguousLength,
      byteLength: 0,
      fork: this.core.tree.fork,
      compatLength: this.core.header.hints.contiguousLength
    }
  }

  _updateSnapshot () {
    const prev = this._snapshot
    const next = this._snapshot = this._getSnapshot()

    if (!prev) return true
    return prev.length !== next.length || prev.fork !== next.fork
  }

  _isWritable () {
    return !this._readonly && !!(this.keyPair && this.keyPair.secretKey)
  }

  close (err) {
    if (this.closing) return this.closing
    this.closing = this._close(err || null)
    return this.closing
  }

  async _close (err) {
    if (this.opened === false) await this.opening

    const i = this.sessions.indexOf(this)
    if (i === -1) return

    this.sessions.splice(i, 1)
    this.readable = false
    this.writable = false
    this.closed = true
    this.opened = false

    const gc = []
    for (const ext of this.extensions.values()) {
      if (ext.session === this) gc.push(ext)
    }
    for (const ext of gc) ext.destroy()

    if (this.replicator !== null) {
      this.replicator.findingPeers -= this._findingPeers
      this.replicator.clearRequests(this.activeRequests, err)
      this.replicator.updateActivity(this._active ? -1 : 0, this)
    }

    this._findingPeers = 0

    if (this.sessions.length) {
      // if this is the last session and we are auto closing, trigger that first to enforce error handling
      if (this.sessions.length === 1 && this.autoClose) await this.sessions[0].close(err)
      // emit "fake" close as this is a session
      this.emit('close', false)
      return
    }

    if (this.replicator !== null) {
      this.replicator.destroy()
    }

    await this.core.close()

    this.emit('close', true)
  }

  clone (keyPair, storage, opts = {}) {
    // TODO: current limitation is no forking
    if ((opts.fork && opts.fork !== 0) || this.fork !== 0) {
      throw BAD_ARGUMENT('Cannot clone a fork')
    }

    const manifest = opts.manifest || defaultSignerManifest(keyPair.publicKey)
    const key = opts.key || (opts.compat !== false ? manifest.signer.publicKey : manifestHash(manifest))

    if (b4a.equals(key, this.key)) {
      throw BAD_ARGUMENT('Clone cannot share verification information')
    }

    const signature = opts.signature === undefined
      ? createVerifier(createManifest(manifest), { compat: isCompat(key, manifest) }).sign(this.core.tree.batch(), keyPair)
      : opts.signature

    const sparse = opts.sparse === false ? false : this.sparse
    const wait = opts.wait === false ? false : this.wait
    const onwait = opts.onwait === undefined ? this.onwait : opts.onwait
    const timeout = opts.timeout === undefined ? this.timeout : opts.timeout

    const Clz = this.constructor

    return new Clz(storage, key, {
      ...opts,
      keyPair,
      sparse,
      wait,
      onwait,
      timeout,
      manifest,
      overwrite: true,
      clone: {
        from: this,
        signature
      }
    })
  }

  replicate (isInitiator, opts = {}) {
    // Only limitation here is that ondiscoverykey doesn't work atm when passing a muxer directly,
    // because it doesn't really make a lot of sense.
    if (Protomux.isProtomux(isInitiator)) return this._attachToMuxer(isInitiator, opts)

    // if same stream is passed twice, ignore the 2nd one before we make sessions etc
    if (isStream(isInitiator) && this._isAttached(isInitiator)) return isInitiator

    const protocolStream = Hypercore.createProtocolStream(isInitiator, opts)
    const noiseStream = protocolStream.noiseStream
    const protocol = noiseStream.userData
    const useSession = !!opts.session

    this._attachToMuxer(protocol, useSession)

    return protocolStream
  }

  _isAttached (stream) {
    return stream.userData && this.replicator && this.replicator.attached(stream.userData)
  }

  _attachToMuxer (mux, useSession) {
    if (this.opened) {
      this._attachToMuxerOpened(mux, useSession)
    } else {
      this.opening.then(this._attachToMuxerOpened.bind(this, mux, useSession), mux.destroy.bind(mux))
    }

    return mux
  }

  _attachToMuxerOpened (mux, useSession) {
    // If the user wants to, we can make this replication run in a session
    // that way the core wont close "under them" during replication
    const session = useSession ? this.session({ active: false }) : null
    this.replicator.attachTo(mux, session)
  }

  get discoveryKey () {
    return this.replicator === null ? null : this.replicator.discoveryKey
  }

  get manifest () {
    return this.core === null ? null : this.core.header.manifest
  }

  get length () {
    if (this._snapshot) return this._snapshot.length
    if (this.core === null) return 0
    if (!this.sparse) return this.contiguousLength
    return this.core.tree.length
  }

  get indexedLength () {
    return this.length
  }

  /**
   * Deprecated. Use `const { byteLength } = await core.info()`.
   */
  get byteLength () {
    if (this._snapshot) return this._snapshot.byteLength
    if (this.core === null) return 0
    if (!this.sparse) return this.contiguousByteLength
    return this.core.tree.byteLength - (this.core.tree.length * this.padding)
  }

  get contiguousLength () {
    return this.core === null ? 0 : Math.min(this.core.tree.length, this.core.header.hints.contiguousLength)
  }

  get contiguousByteLength () {
    return 0
  }

  get fork () {
    return this.core === null ? 0 : this.core.tree.fork
  }

  get peers () {
    return this.replicator === null ? [] : this.replicator.peers
  }

  get encryptionKey () {
    return this.encryption && this.encryption.key
  }

  get padding () {
    return this.encryption === null ? 0 : this.encryption.padding
  }

  ready () {
    return this.opening
  }

  _onupload (index, value, from) {
    const byteLength = value.byteLength - this.padding

    for (let i = 0; i < this.sessions.length; i++) {
      this.sessions[i].emit('upload', index, byteLength, from)
    }
  }

  _oninvalid (err, req, res, from) {
    for (let i = 0; i < this.sessions.length; i++) {
      this.sessions[i].emit('verification-error', err, req, res, from)
    }
  }

  async _oncoreconflict (proof, from) {
    await this.replicator.onconflict(from)

    for (const s of this.sessions) s.emit('conflict', proof.upgrade.length, proof.fork, proof)

    const err = new Error('Two conflicting signatures exist for length ' + proof.upgrade.length)
    await this._closeAllSessions(err)
  }

  async _closeAllSessions (err) {
    // this.sessions modifies itself when a session closes
    // This way we ensure we indeed iterate over all sessions
    const sessions = [...this.sessions]

    const all = []
    for (const s of sessions) all.push(s.close(err))
    await Promise.allSettled(all)
  }

  _oncoreupdate (status, bitfield, value, from) {
    if (status !== 0) {
      const truncatedNonSparse = (status & 0b1000) !== 0
      const appendedNonSparse = (status & 0b0100) !== 0
      const truncated = (status & 0b0010) !== 0
      const appended = (status & 0b0001) !== 0

      if (truncated) {
        this.replicator.ontruncate(bitfield.start, bitfield.length)
      }

      if ((status & 0b10011) !== 0) {
        this.replicator.onupgrade()
      }

      if (status & 0b10000) {
        for (let i = 0; i < this.sessions.length; i++) {
          const s = this.sessions[i]

          if (s.encryption && s.encryption.compat !== this.core.compat) {
            s.encryption = new BlockEncryption(s.encryption.key, this.key, { compat: this.core.compat, isBlockKey: s.encryption.isBlockKey })
          }
        }

        for (let i = 0; i < this.sessions.length; i++) {
          this.sessions[i].emit('manifest')
        }
      }

      for (let i = 0; i < this.sessions.length; i++) {
        const s = this.sessions[i]

        if (truncated) {
          if (s.cache) s.cache.clear()

          // If snapshotted, make sure to update our compat so we can fail gets
          if (s._snapshot && bitfield.start < s._snapshot.compatLength) s._snapshot.compatLength = bitfield.start
        }

        if (s.sparse ? truncated : truncatedNonSparse) {
          s.emit('truncate', bitfield.start, this.core.tree.fork)
        }

        // For sparse sessions, immediately emit appends. If non-sparse, emit if contig length has updated
        if (s.sparse ? appended : appendedNonSparse) {
          s.emit('append')
        }
      }

      const contig = this.core.header.hints.contiguousLength

      // When the contig length catches up, broadcast the non-sparse length to peers
      if (appendedNonSparse && contig === this.core.tree.length) {
        for (const peer of this.peers) {
          if (peer.broadcastedNonSparse) continue

          peer.broadcastRange(0, contig)
          peer.broadcastedNonSparse = true
        }
      }
    }

    if (bitfield) {
      this.replicator.onhave(bitfield.start, bitfield.length, bitfield.drop)
    }

    if (value) {
      const byteLength = value.byteLength - this.padding

      for (let i = 0; i < this.sessions.length; i++) {
        this.sessions[i].emit('download', bitfield.start, byteLength, from)
      }
    }
  }

  _onpeerupdate (added, peer) {
    const name = added ? 'peer-add' : 'peer-remove'

    for (let i = 0; i < this.sessions.length; i++) {
      this.sessions[i].emit(name, peer)

      if (added) {
        for (const ext of this.sessions[i].extensions.values()) {
          peer.extensions.set(ext.name, ext)
        }
      }
    }
  }

  async setUserData (key, value, { flush = false } = {}) {
    if (this.opened === false) await this.opening
    return this.core.userData(key, value, flush)
  }

  async getUserData (key) {
    if (this.opened === false) await this.opening
    for (const { key: savedKey, value } of this.core.header.userData) {
      if (key === savedKey) return value
    }
    return null
  }

  createTreeBatch () {
    return this.core.tree.batch()
  }

  findingPeers () {
    this._findingPeers++
    if (this.replicator !== null && !this.closing) this.replicator.findingPeers++

    let once = true

    return () => {
      if (this.closing || !once) return
      once = false
      this._findingPeers--
      if (this.replicator !== null && --this.replicator.findingPeers === 0) {
        this.replicator.updateAll()
      }
    }
  }

  async info (opts) {
    if (this.opened === false) await this.opening

    return Info.from(this, opts)
  }

  async update (opts) {
    if (this.opened === false) await this.opening
    if (this.closing !== null) return false

    if (this.writable && (!opts || opts.force !== true)) {
      if (!this.snapshotted) return false
      return this._updateSnapshot()
    }

    const remoteWait = this._shouldWait(opts, this.replicator.findingPeers > 0)

    let upgraded = false

    if (await this.replicator.applyPendingReorg()) {
      upgraded = true
    }

    if (!upgraded && remoteWait) {
      const activeRequests = (opts && opts.activeRequests) || this.activeRequests
      const req = this.replicator.addUpgrade(activeRequests)

      upgraded = await req.promise
    }

    if (!upgraded) return false
    if (this.snapshotted) return this._updateSnapshot()
    return true
  }

  batch ({ checkout = -1, autoClose = true, session = true, restore = false } = {}) {
    return new Batch(session ? this.session() : this, checkout, autoClose, restore)
  }

  async seek (bytes, opts) {
    if (this.opened === false) await this.opening

    const tree = (opts && opts.tree) || this.core.tree
    const s = tree.seek(bytes, this.padding)

    const offset = await s.update()
    if (offset) return offset

    if (this.closing !== null) throw SESSION_CLOSED()

    if (!this._shouldWait(opts, this.wait)) return null

    const activeRequests = (opts && opts.activeRequests) || this.activeRequests
    const req = this.replicator.addSeek(activeRequests, s)

    const timeout = opts && opts.timeout !== undefined ? opts.timeout : this.timeout
    if (timeout) req.context.setTimeout(req, timeout)

    return req.promise
  }

  async has (start, end = start + 1) {
    if (this.opened === false) await this.opening

    const length = end - start
    if (length <= 0) return false
    if (length === 1) return this.core.bitfield.get(start)

    const i = this.core.bitfield.firstUnset(start)
    return i === -1 || i >= end
  }

  async get (index, opts) {
    if (this.opened === false) await this.opening
    if (this.closing !== null) throw SESSION_CLOSED()
    if (this._snapshot !== null && index >= this._snapshot.compatLength) throw SNAPSHOT_NOT_AVAILABLE()

    const encoding = (opts && opts.valueEncoding && c.from(opts.valueEncoding)) || this.valueEncoding

    let req = this.cache && this.cache.get(index)
    if (!req) req = this._get(index, opts)

    let block = await req
    if (!block) return null

    if (this.encryption && (!opts || opts.decrypt !== false)) {
      // Copy the block as it might be shared with other sessions.
      block = b4a.from(block)

      this.encryption.decrypt(index, block)
    }

    return this._decode(encoding, block)
  }

  async clear (start, end = start + 1, opts) {
    if (this.opened === false) await this.opening
    if (this.closing !== null) throw SESSION_CLOSED()

    if (typeof end === 'object') {
      opts = end
      end = start + 1
    }

    const cleared = (opts && opts.diff) ? { blocks: 0 } : null

    if (start >= end) return cleared
    if (start >= this.length) return cleared

    await this.core.clear(start, end, cleared)

    return cleared
  }

  async purge () {
    await this._closeAllSessions(null)
    await this.core.purge()
  }

  async _get (index, opts) {
    let block

    if (this.core.bitfield.get(index)) {
      const tree = (opts && opts.tree) || this.core.tree
      block = this.core.blocks.get(index, tree)

      if (this.cache) this.cache.set(index, block)
    } else {
      if (!this._shouldWait(opts, this.wait)) return null

      if (opts && opts.onwait) opts.onwait(index, this)
      if (this.onwait) this.onwait(index, this)

      const activeRequests = (opts && opts.activeRequests) || this.activeRequests

      const req = this.replicator.addBlock(activeRequests, index)

      const timeout = opts && opts.timeout !== undefined ? opts.timeout : this.timeout
      if (timeout) req.context.setTimeout(req, timeout)

      block = this._cacheOnResolve(index, req.promise, this.core.tree.fork)
    }

    return block
  }

  async _cacheOnResolve (index, req, fork) {
    const block = await req

    if (this.cache && fork === this.core.tree.fork) {
      this.cache.set(index, Promise.resolve(block))
    }

    return block
  }

  _shouldWait (opts, defaultValue) {
    if (opts) {
      if (opts.wait === false) return false
      if (opts.wait === true) return true
    }
    return defaultValue
  }

  createReadStream (opts) {
    return new ReadStream(this, opts)
  }

  createWriteStream (opts) {
    return new WriteStream(this, opts)
  }

  createByteStream (opts) {
    return new ByteStream(this, opts)
  }

  download (range) {
    const req = this._download(range)

    // do not crash in the background...
    req.catch(noop)

    return new Download(req)
  }

  async _download (range) {
    if (this.opened === false) await this.opening

    const activeRequests = (range && range.activeRequests) || this.activeRequests

    return this.replicator.addRange(activeRequests, range)
  }

  // TODO: get rid of this / deprecate it?
  undownload (range) {
    range.destroy(null)
  }

  // TODO: get rid of this / deprecate it?
  cancel (request) {
    // Do nothing for now
  }

  async truncate (newLength = 0, opts = {}) {
    if (this.opened === false) await this.opening

    const {
      fork = this.core.tree.fork + 1,
      keyPair = this.keyPair,
      signature = null
    } = typeof opts === 'number' ? { fork: opts } : opts

    const writable = !this._readonly && !!(signature || (keyPair && keyPair.secretKey))
    if (writable === false && (newLength > 0 || fork !== this.core.tree.fork)) throw SESSION_NOT_WRITABLE()

    await this.core.truncate(newLength, fork, { keyPair, signature })

    // TODO: Should propagate from an event triggered by the oplog
    this.replicator.updateAll()
  }

  async append (blocks, opts = {}) {
    if (this.opened === false) await this.opening

    const { keyPair = this.keyPair, signature = null } = opts
    const writable = !this._readonly && !!(signature || (keyPair && keyPair.secretKey))

    if (writable === false) throw SESSION_NOT_WRITABLE()

    blocks = Array.isArray(blocks) ? blocks : [blocks]

    const preappend = this.encryption && this._preappend

    const buffers = this.encodeBatch !== null ? this.encodeBatch(blocks) : new Array(blocks.length)

    if (this.encodeBatch === null) {
      for (let i = 0; i < blocks.length; i++) {
        buffers[i] = this._encode(this.valueEncoding, blocks[i])
      }
    }

    return this.core.append(buffers, { keyPair, signature, preappend })
  }

  async treeHash (length) {
    if (length === undefined) {
      await this.ready()
      length = this.core.tree.length
    }

    const roots = await this.core.tree.getRoots(length)
    return this.crypto.tree(roots)
  }

  registerExtension (name, handlers = {}) {
    if (this.extensions.has(name)) {
      const ext = this.extensions.get(name)
      ext.handlers = handlers
      ext.encoding = c.from(handlers.encoding || c.buffer)
      ext.session = this
      return ext
    }

    const ext = {
      name,
      handlers,
      encoding: c.from(handlers.encoding || c.buffer),
      session: this,
      send (message, peer) {
        const buffer = c.encode(this.encoding, message)
        peer.extension(name, buffer)
      },
      broadcast (message) {
        const buffer = c.encode(this.encoding, message)
        for (const peer of this.session.peers) {
          peer.extension(name, buffer)
        }
      },
      destroy () {
        for (const peer of this.session.peers) {
          if (peer.extensions.get(name) === ext) peer.extensions.delete(name)
        }
        this.session.extensions.delete(name)
      },
      _onmessage (state, peer) {
        const m = this.encoding.decode(state)
        if (this.handlers.onmessage) this.handlers.onmessage(m, peer)
      }
    }

    this.extensions.set(name, ext)
    for (const peer of this.peers) {
      peer.extensions.set(name, ext)
    }

    return ext
  }

  _encode (enc, val) {
    const state = { start: this.padding, end: this.padding, buffer: null }

    if (b4a.isBuffer(val)) {
      if (state.start === 0) return val
      state.end += val.byteLength
    } else if (enc) {
      enc.preencode(state, val)
    } else {
      val = b4a.from(val)
      if (state.start === 0) return val
      state.end += val.byteLength
    }

    state.buffer = b4a.allocUnsafe(state.end)

    if (enc) enc.encode(state, val)
    else state.buffer.set(val, state.start)

    return state.buffer
  }

  _decode (enc, block) {
    if (this.padding) block = block.subarray(this.padding)
    if (enc) return c.decode(enc, block)
    return block
  }
}

function noop () {}

function isStream (s) {
  return typeof s === 'object' && s && typeof s.pipe === 'function'
}

function isRandomAccessClass (fn) {
  return !!(typeof fn === 'function' && fn.prototype && typeof fn.prototype.open === 'function')
}

function toHex (buf) {
  return buf && b4a.toString(buf, 'hex')
}

function preappend (blocks) {
  const offset = this.core.tree.length
  const fork = this.core.tree.fork

  for (let i = 0; i < blocks.length; i++) {
    this.encryption.encrypt(offset + i, blocks[i], fork)
  }
}

function ensureEncryption (core, opts) {
  if (!opts.encryptionKey) return
  // Only override the block encryption if it's either not already set or if
  // the caller provided a different key.
  if (core.encryption && b4a.equals(core.encryption.key, opts.encryptionKey) && core.encryption.compat === core.core.compat) return
  core.encryption = new BlockEncryption(opts.encryptionKey, core.key, { compat: core.core ? core.core.compat : true, isBlockKey: opts.isBlockKey })
}

function createCache (cache) {
  return cache === true ? new Xache({ maxSize: 65536, maxAge: 0 }) : (cache || null)
}

},{"./lib/batch":30,"./lib/block-encryption":33,"./lib/core":37,"./lib/download":38,"./lib/info":39,"./lib/manifest":40,"./lib/replicator":48,"./lib/streams":49,"@hyperswarm/secret-stream":1,"b4a":4,"compact-encoding":16,"events":22,"hypercore-crypto":26,"hypercore-errors":27,"hypercore-id-encoding":28,"is-options":50,"protomux":58,"random-access-file":61,"xache":130,"z32":133}],30:[function(require,module,exports){
const { BLOCK_NOT_AVAILABLE, SESSION_CLOSED } = require('hypercore-errors')
const EventEmitter = require('events')
const c = require('compact-encoding')
const b4a = require('b4a')

module.exports = class HypercoreBatch extends EventEmitter {
  constructor (session, checkoutLength, autoClose, restore) {
    super()

    this.session = session
    this.opened = false
    this.closed = false
    this.opening = null
    this.closing = null
    this.writable = true // always writable...
    this.autoClose = autoClose
    this.restore = restore
    this.fork = 0

    this._appends = []
    this._appendsActual = null
    this._checkoutLength = checkoutLength
    this._byteLength = 0
    this._sessionLength = 0
    this._sessionByteLength = 0
    this._sessionBatch = null
    this._flushing = null

    this.opening = this.ready().catch(noop)
  }

  get id () {
    return this.session.id
  }

  get key () {
    return this.session.key
  }

  get discoveryKey () {
    return this.session.discoveryKey
  }

  get indexedLength () {
    return Math.min(this._sessionLength, this.session.core === null ? 0 : this.session.core.tree.length)
  }

  get flushedLength () {
    return this._sessionLength
  }

  get indexedByteLength () {
    return this._sessionByteLength
  }

  get length () {
    return this._sessionLength + this._appends.length
  }

  get byteLength () {
    return this._sessionByteLength + this._byteLength
  }

  get core () {
    return this.session.core
  }

  get manifest () {
    return this.session.manifest
  }

  async ready () {
    await this.session.ready()
    if (this.opened) return

    if (this._checkoutLength !== -1) {
      const batch = await this.session.core.tree.restoreBatch(this._checkoutLength)
      batch.treeLength = this._checkoutLength
      if (this.opened) return
      this._sessionLength = batch.length
      this._sessionByteLength = batch.byteLength
      this._sessionBatch = batch
    } else {
      const last = this.restore ? this.session.core.bitfield.findFirst(false, this.session.length) : 0

      if (last > this.session.length) {
        const batch = await this.session.core.tree.restoreBatch(last)
        if (this.opened) return
        this._sessionLength = batch.length
        this._sessionByteLength = batch.byteLength - this.session.padding * batch.length
        this._sessionBatch = batch
      } else {
        this._sessionLength = this.session.length
        this._sessionByteLength = this.session.byteLength
        this._sessionBatch = this.session.createTreeBatch()
      }
    }

    this._appendsActual = this.session.encryption ? [] : this._appends
    this.fork = this.session.fork
    this.opened = true
    this.emit('ready')
  }

  async has (index) {
    if (this.opened === false) await this.ready()
    if (index >= this._sessionLength) return index < this.length
    return this.session.has(index)
  }

  async update (opts) {
    if (this.opened === false) await this.ready()
    await this.session.update(opts)
  }

  treeHash () {
    return this._sessionBatch.hash()
  }

  setUserData (key, value, opts) {
    return this.session.setUserData(key, value, opts)
  }

  getUserData (key, opts) {
    return this.session.getUserData(key, opts)
  }

  async info (opts) {
    const session = this.session
    const info = await session.info(opts)

    info.length = this._sessionLength

    if (info.contiguousLength >= info.length) {
      info.contiguousLength = info.length += this._appends.length
    } else {
      info.length += this._appends.length
    }

    info.byteLength = this._sessionByteLength + this._byteLength

    return info
  }

  async seek (bytes, opts = {}) {
    if (this.opened === false) await this.opening
    if (this.closing) throw SESSION_CLOSED()

    if (bytes < this._sessionByteLength) return await this.session.seek(bytes, { ...opts, tree: this._sessionBatch })

    bytes -= this._sessionByteLength

    let i = 0

    for (const blk of this._appends) {
      if (bytes < blk.byteLength) return [this._sessionLength + i, bytes]
      i++
      bytes -= blk.byteLength
    }

    if (bytes === 0) return [this._sessionLength + i, 0]

    throw BLOCK_NOT_AVAILABLE()
  }

  async get (index, opts) {
    if (this.opened === false) await this.opening
    if (this.closing) throw SESSION_CLOSED()

    const length = this._sessionLength
    if (index < length) return this.session.get(index, { ...opts, tree: this._sessionBatch })

    const buffer = this._appends[index - length] || null
    if (!buffer) throw BLOCK_NOT_AVAILABLE()

    const encoding = (opts && opts.valueEncoding && c.from(opts.valueEncoding)) || this.session.valueEncoding
    if (!encoding) return buffer

    return c.decode(encoding, buffer)
  }

  async _waitForFlush () {
    // wait for any pending flush...
    while (this._flushing) {
      await this._flushing
      await Promise.resolve() // yield in case a new flush is queued
    }
  }

  async restoreBatch (length) {
    if (this.opened === false) await this.opening
    if (length >= this._sessionLength) return this.createTreeBatch(length)
    return this.session.core.tree.restoreBatch(length)
  }

  createTreeBatch (length, blocks = []) {
    if (!length && length !== 0) length = this.length + blocks.length

    const maxLength = this.length + blocks.length
    const b = this._sessionBatch.clone()
    const len = Math.min(length, this.length)

    if (len < this._sessionLength || length > maxLength) return null

    for (let i = 0; i < len - this._sessionLength; i++) {
      b.append(this._appendsActual[i])
    }

    if (len < this.length) return b

    for (let i = 0; i < length - len; i++) {
      b.append(this._appendsActual === this._appends ? blocks[i] : this._encrypt(b.length, blocks[i]))
    }

    return b
  }

  async truncate (newLength = 0, opts = {}) {
    if (this.opened === false) await this.opening
    if (this.closing) throw SESSION_CLOSED()

    // wait for any pending flush... (prop needs a lock)
    await this._waitForFlush()

    if (typeof opts === 'number') opts = { fork: opts }
    const { fork = this.fork + 1, force = false } = opts

    const length = this._sessionLength
    if (newLength < length) {
      if (!force) throw new Error('Cannot truncate committed blocks')
      this._appends.length = 0
      this._byteLength = 0
      await this.session.truncate(newLength, { fork, force: true, ...opts })
      this._sessionLength = this.session.length
      this._sessionByteLength = this.session.byteLength
      this._sessionBatch = this.session.createTreeBatch()
    } else {
      for (let i = newLength - length; i < this._appends.length; i++) this._byteLength -= this._appends[i].byteLength
      this._appends.length = newLength - length
    }

    this.fork = fork

    this.emit('truncate', newLength, this.fork)
  }

  async append (blocks) {
    const session = this.session

    if (this.opened === false) await this.opening
    if (this.closing) throw SESSION_CLOSED()

    // wait for any pending flush... (prop needs a lock)
    await this._waitForFlush()

    blocks = Array.isArray(blocks) ? blocks : [blocks]

    const buffers = session.encodeBatch !== null
      ? session.encodeBatch(blocks)
      : new Array(blocks.length)

    if (session.encodeBatch === null) {
      for (let i = 0; i < blocks.length; i++) {
        const buffer = this._encode(session.valueEncoding, blocks[i])
        buffers[i] = buffer
        this._byteLength += buffer.byteLength
      }
    }
    if (this._appends !== this._appendsActual) {
      for (let i = 0; i < buffers.length; i++) {
        this._appendsActual.push(this._encrypt(this._sessionLength + this._appendsActual.length, buffers[i]))
      }
    }

    this._appends.push(...buffers)

    const info = { length: this.length, byteLength: this.byteLength }
    this.emit('append')

    return info
  }

  _encode (enc, val) {
    const state = { start: 0, end: 0, buffer: null }

    if (b4a.isBuffer(val)) {
      if (state.start === 0) return val
      state.end += val.byteLength
    } else if (enc) {
      enc.preencode(state, val)
    } else {
      val = b4a.from(val)
      if (state.start === 0) return val
      state.end += val.byteLength
    }

    state.buffer = b4a.allocUnsafe(state.end)

    if (enc) enc.encode(state, val)
    else state.buffer.set(val, state.start)

    return state.buffer
  }

  _encrypt (index, buffer) {
    const block = b4a.allocUnsafe(buffer.byteLength + 8)
    block.set(buffer, 8)
    this.session.encryption.encrypt(index, block, this.fork)
    return block
  }

  async flush (opts = {}) {
    if (this.opened === false) await this.opening
    if (this.closing) throw SESSION_CLOSED()

    const { length = this.length, keyPair = this.session.keyPair, signature = null, pending = !signature && !keyPair } = opts

    while (this._flushing) await this._flushing
    this._flushing = this._flush(length, keyPair, signature, pending)

    let flushed = false

    try {
      flushed = await this._flushing
    } finally {
      this._flushing = null
    }

    if (this.autoClose) await this.close()

    return flushed
  }

  async _flush (length, keyPair, signature, pending) { // TODO: make this safe to interact with a parallel truncate...
    if (this._sessionBatch.fork !== this.session.fork) return false // no truncs supported atm

    if (this.session.replicator._upgrade) {
      for (const req of this.session.replicator._upgrade.inflight) {
        // yield to the remote inflight upgrade, TODO: if the remote upgrade fails, retry flushing...
        if (req.upgrade && (req.upgrade.start + req.upgrade.length) > length) {
          return false
        }
      }
    }

    const flushingLength = Math.min(length - this._sessionLength, this._appends.length)
    if (flushingLength <= 0) {
      if (this._sessionLength > this.core.tree.length && length > this.core.tree.length && !pending) {
        const batch = await this.restoreBatch(length)
        const info = await this.core.insertBatch(batch, [], { keyPair, signature, pending, treeLength: length })
        return info !== null
      }
      return true
    }

    const batch = this.createTreeBatch(this._sessionLength + flushingLength)
    if (batch === null) return false

    const info = await this.core.insertBatch(batch, this._appendsActual, { keyPair, signature, pending, treeLength: this._sessionLength })
    if (info === null) return false

    const delta = info.byteLength - this._sessionByteLength
    const newBatch = info.length !== this.session.length ? await this.session.core.tree.restoreBatch(info.length) : this.session.createTreeBatch()

    this._sessionLength = info.length
    this._sessionByteLength = info.byteLength
    this._sessionBatch = newBatch

    const same = this._appends === this._appendsActual

    this._appends = this._appends.slice(flushingLength)
    this._appendsActual = same ? this._appends : this._appendsActual.slice(flushingLength)
    this._byteLength -= delta

    this.emit('flush')

    return true
  }

  close () {
    if (!this.closing) this.closing = this._close()
    return this.closing
  }

  async _close () {
    this._clearAppends()

    await this.session.close()

    this.closed = true
    this.emit('close')
  }

  _clearAppends () {
    this._appends = []
    this._appendsActual = []
    this._byteLength = 0
    this.fork = 0
  }
}

function noop () {}

},{"b4a":4,"compact-encoding":16,"events":22,"hypercore-errors":27}],31:[function(require,module,exports){
const c = require('compact-encoding')
const { oplog } = require('./messages')

module.exports = class BigHeader {
  constructor (storage) {
    this.storage = storage
  }

  async load (external) {
    const buf = await new Promise((resolve, reject) => {
      this.storage.read(external.start, external.length, (err, buf) => {
        if (err) return reject(err)
        resolve(buf)
      })
    })

    const header = c.decode(oplog.header, buf)
    header.external = external
    return header
  }

  async flush (header) {
    const external = header.external || { start: 0, length: 0 }
    header.external = null

    const buf = c.encode(oplog.header, header)

    let start = 0
    if (buf.byteLength > external.start) {
      start = external.start + external.length
      const rem = start & 4095
      if (rem > 0) start += (4096 - rem)
    }

    header.external = { start, length: buf.byteLength }

    await new Promise((resolve, reject) => {
      this.storage.write(start, buf, (err) => {
        if (err) return reject(err)
        resolve()
      })
    })

    return header
  }

  close () {
    return new Promise((resolve, reject) => {
      this.storage.close((err) => {
        if (err) return reject(err)
        resolve()
      })
    })
  }
}

},{"./messages":42,"compact-encoding":16}],32:[function(require,module,exports){
const BigSparseArray = require('big-sparse-array')
const b4a = require('b4a')
const quickbit = require('./compat').quickbit

const BITS_PER_PAGE = 32768
const BYTES_PER_PAGE = BITS_PER_PAGE / 8
const WORDS_PER_PAGE = BYTES_PER_PAGE / 4
const BITS_PER_SEGMENT = 2097152
const BYTES_PER_SEGMENT = BITS_PER_SEGMENT / 8
const WORDS_PER_SEGMENT = BYTES_PER_SEGMENT / 4
const INITIAL_WORDS_PER_SEGMENT = 1024
const PAGES_PER_SEGMENT = BITS_PER_SEGMENT / BITS_PER_PAGE
const SEGMENT_GROWTH_FACTOR = 4

class BitfieldPage {
  constructor (index, segment) {
    this.dirty = false
    this.index = index
    this.offset = index * BYTES_PER_PAGE - segment.offset
    this.bitfield = null
    this.segment = segment

    segment.add(this)
  }

  get tree () {
    return this.segment.tree
  }

  get (index) {
    return quickbit.get(this.bitfield, index)
  }

  set (index, val) {
    if (quickbit.set(this.bitfield, index, val)) {
      this.tree.update(this.offset * 8 + index)
    }
  }

  setRange (start, length, val) {
    quickbit.fill(this.bitfield, val, start, start + length)

    let i = Math.floor(start / 128)
    const n = i + Math.ceil(length / 128)

    while (i <= n) this.tree.update(this.offset * 8 + i++ * 128)
  }

  findFirst (val, position) {
    return quickbit.findFirst(this.bitfield, val, position)
  }

  findLast (val, position) {
    return quickbit.findLast(this.bitfield, val, position)
  }

  count (start, length, val) {
    const end = start + length

    let i = start
    let c = 0

    while (length > 0) {
      const l = this.findFirst(val, i)
      if (l === -1 || l >= end) return c

      const h = this.findFirst(!val, l + 1)
      if (h === -1 || h >= end) return c + end - l

      c += h - l
      length -= h - i
      i = h
    }

    return c
  }
}

class BitfieldSegment {
  constructor (index, bitfield) {
    this.index = index
    this.offset = index * BYTES_PER_SEGMENT
    this.tree = quickbit.Index.from(bitfield, BYTES_PER_SEGMENT)
    this.pages = new Array(PAGES_PER_SEGMENT)
  }

  get bitfield () {
    return this.tree.field
  }

  add (page) {
    const i = page.index - this.index * PAGES_PER_SEGMENT
    this.pages[i] = page

    const start = i * WORDS_PER_PAGE
    const end = start + WORDS_PER_PAGE

    if (end >= this.bitfield.length) this.reallocate(end)

    page.bitfield = this.bitfield.subarray(start, end)
  }

  reallocate (length) {
    let target = this.bitfield.length
    while (target < length) target *= SEGMENT_GROWTH_FACTOR

    const bitfield = new Uint32Array(target)
    bitfield.set(this.bitfield)

    this.tree = quickbit.Index.from(bitfield, BYTES_PER_SEGMENT)

    for (let i = 0; i < this.pages.length; i++) {
      const page = this.pages[i]
      if (!page) continue

      const start = i * WORDS_PER_PAGE
      const end = start + WORDS_PER_PAGE

      page.bitfield = bitfield.subarray(start, end)
    }
  }

  findFirst (val, position) {
    position = this.tree.skipFirst(!val, position)

    let j = position & (BITS_PER_PAGE - 1)
    let i = (position - j) / BITS_PER_PAGE

    if (i >= PAGES_PER_SEGMENT) return -1

    while (i < this.pages.length) {
      const p = this.pages[i]

      let index = -1

      if (p) index = p.findFirst(val, j)
      else if (!val) index = j

      if (index !== -1) return i * BITS_PER_PAGE + index

      j = 0
      i++
    }

    return -1
  }

  findLast (val, position) {
    position = this.tree.skipLast(!val, position)

    let j = position & (BITS_PER_PAGE - 1)
    let i = (position - j) / BITS_PER_PAGE

    if (i >= PAGES_PER_SEGMENT) return -1

    while (i >= 0) {
      const p = this.pages[i]

      let index = -1

      if (p) index = p.findLast(val, j)
      else if (!val) index = j

      if (index !== -1) return i * BITS_PER_PAGE + index

      j = BITS_PER_PAGE - 1
      i--
    }

    return -1
  }
}

module.exports = class Bitfield {
  constructor (storage, buffer) {
    this.unflushed = []
    this.storage = storage
    this.resumed = !!(buffer && buffer.byteLength >= 4)

    this._pages = new BigSparseArray()
    this._segments = new BigSparseArray()

    const view = this.resumed
      ? new Uint32Array(
        buffer.buffer,
        buffer.byteOffset,
        Math.floor(buffer.byteLength / 4)
      )
      : new Uint32Array(INITIAL_WORDS_PER_SEGMENT)

    for (let i = 0; i < view.length; i += WORDS_PER_SEGMENT) {
      let bitfield = view.subarray(i, i + (WORDS_PER_SEGMENT))
      let length = WORDS_PER_SEGMENT

      if (i === 0) {
        length = INITIAL_WORDS_PER_SEGMENT
        while (length < bitfield.length) length *= SEGMENT_GROWTH_FACTOR
      }

      if (bitfield.length !== length) {
        const copy = new Uint32Array(length)
        copy.set(bitfield, 0)
        bitfield = copy
      }

      const segment = new BitfieldSegment(i / (WORDS_PER_SEGMENT), bitfield)
      this._segments.set(segment.index, segment)

      for (let j = 0; j < bitfield.length; j += WORDS_PER_PAGE) {
        const page = new BitfieldPage((i + j) / WORDS_PER_PAGE, segment)
        this._pages.set(page.index, page)
      }
    }
  }

  getBitfield (index, length) {
    const j = index & (BITS_PER_PAGE - 1)
    const i = (index - j) / BITS_PER_PAGE

    const p = this._pages.get(i)
    return p || null
  }

  get (index) {
    const j = index & (BITS_PER_PAGE - 1)
    const i = (index - j) / BITS_PER_PAGE

    const p = this._pages.get(i)

    return p ? p.get(j) : false
  }

  set (index, val) {
    const j = index & (BITS_PER_PAGE - 1)
    const i = (index - j) / BITS_PER_PAGE

    let p = this._pages.get(i)

    if (!p && val) {
      const k = Math.floor(i / PAGES_PER_SEGMENT)
      const s = this._segments.get(k) || this._segments.set(k, new BitfieldSegment(k, new Uint32Array(k === 0 ? INITIAL_WORDS_PER_SEGMENT : WORDS_PER_SEGMENT)))

      p = this._pages.set(i, new BitfieldPage(i, s))
    }

    if (p) {
      p.set(j, val)

      if (!p.dirty) {
        p.dirty = true
        this.unflushed.push(p)
      }
    }
  }

  setRange (start, length, val) {
    let j = start & (BITS_PER_PAGE - 1)
    let i = (start - j) / BITS_PER_PAGE

    while (length > 0) {
      let p = this._pages.get(i)

      if (!p && val) {
        const k = Math.floor(i / PAGES_PER_SEGMENT)
        const s = this._segments.get(k) || this._segments.set(k, new BitfieldSegment(k, new Uint32Array(k === 0 ? INITIAL_WORDS_PER_SEGMENT : WORDS_PER_SEGMENT)))

        p = this._pages.set(i, new BitfieldPage(i, s))
      }

      const end = Math.min(j + length, BITS_PER_PAGE)
      const range = end - j

      if (p) {
        p.setRange(j, range, val)

        if (!p.dirty) {
          p.dirty = true
          this.unflushed.push(p)
        }
      }

      j = 0
      i++
      length -= range
    }
  }

  findFirst (val, position) {
    let j = position & (BITS_PER_SEGMENT - 1)
    let i = (position - j) / BITS_PER_SEGMENT

    while (i < this._segments.maxLength) {
      const s = this._segments.get(i)

      let index = -1

      if (s) index = s.findFirst(val, j)
      else if (!val) index = j

      if (index !== -1) return i * BITS_PER_SEGMENT + index

      j = 0
      i++
    }

    return val ? -1 : position
  }

  firstSet (position) {
    return this.findFirst(true, position)
  }

  firstUnset (position) {
    return this.findFirst(false, position)
  }

  findLast (val, position) {
    let j = position & (BITS_PER_SEGMENT - 1)
    let i = (position - j) / BITS_PER_SEGMENT

    while (i >= 0) {
      const s = this._segments.get(i)

      let index = -1

      if (s) index = s.findLast(val, j)
      else if (!val) index = j

      if (index !== -1) return i * BITS_PER_SEGMENT + index

      j = BITS_PER_SEGMENT - 1
      i--
    }

    return -1
  }

  lastSet (position) {
    return this.findLast(true, position)
  }

  lastUnset (position) {
    return this.findLast(false, position)
  }

  count (start, length, val) {
    let j = start & (BITS_PER_PAGE - 1)
    let i = (start - j) / BITS_PER_PAGE
    let c = 0

    while (length > 0) {
      const p = this._pages.get(i)

      const end = Math.min(j + length, BITS_PER_PAGE)
      const range = end - j

      if (p) c += p.count(j, range, val)
      else if (!val) c += range

      j = 0
      i++
      length -= range
    }

    return c
  }

  countSet (start, length) {
    return this.count(start, length, true)
  }

  countUnset (start, length) {
    return this.count(start, length, false)
  }

  * want (start, length) {
    const j = start & (BITS_PER_SEGMENT - 1)
    let i = (start - j) / BITS_PER_SEGMENT

    while (length > 0) {
      const s = this._segments.get(i)

      if (s) {
        // We always send at least 4 KiB worth of bitfield in a want, rounding
        // to the nearest 4 KiB.
        const end = ceilTo(clamp(length / 8, 4096, BYTES_PER_SEGMENT), 4096)

        yield {
          start: i * BITS_PER_SEGMENT,
          bitfield: s.bitfield.subarray(0, end / 4)
        }
      }

      i++
      length -= BITS_PER_SEGMENT
    }
  }

  clear () {
    return new Promise((resolve, reject) => {
      this.storage.truncate(0, (err) => {
        if (err) return reject(err)
        this._pages = new BigSparseArray()
        this.unflushed = []
        resolve()
      })
    })
  }

  close () {
    return new Promise((resolve, reject) => {
      this.storage.close((err) => {
        if (err) reject(err)
        else resolve()
      })
    })
  }

  flush () {
    return new Promise((resolve, reject) => {
      if (!this.unflushed.length) return resolve()

      const self = this
      let missing = this.unflushed.length
      let error = null

      for (const page of this.unflushed) {
        const buf = b4a.from(
          page.bitfield.buffer,
          page.bitfield.byteOffset,
          page.bitfield.byteLength
        )

        page.dirty = false
        this.storage.write(page.index * BYTES_PER_PAGE, buf, done)
      }

      function done (err) {
        if (err) error = err
        if (--missing) return
        if (error) return reject(error)
        self.unflushed = []
        resolve()
      }
    })
  }

  static open (storage, tree = null) {
    return new Promise((resolve, reject) => {
      storage.stat((err, st) => {
        if (err) return resolve(new Bitfield(storage, null))
        let size = st.size - (st.size & 3)
        if (!size) return resolve(new Bitfield(storage, null))
        if (tree) size = Math.min(size, ceilTo(tree.length / 8, 4096))
        storage.read(0, size, (err, data) => {
          if (err) return reject(err)
          resolve(new Bitfield(storage, data))
        })
      })
    })
  }
}

function clamp (n, min, max) {
  return Math.min(Math.max(n, min), max)
}

function ceilTo (n, multiple = 1) {
  const remainder = n % multiple
  if (remainder === 0) return n
  return n + multiple - remainder
}

},{"./compat":36,"b4a":4,"big-sparse-array":10}],33:[function(require,module,exports){
const sodium = require('sodium-universal')
const c = require('compact-encoding')
const b4a = require('b4a')
const { BLOCK_ENCRYPTION } = require('./caps')

const nonce = b4a.alloc(sodium.crypto_stream_NONCEBYTES)

module.exports = class BlockEncryption {
  constructor (encryptionKey, hypercoreKey, { isBlockKey = false, compat = true } = {}) {
    const subKeys = b4a.alloc(2 * sodium.crypto_stream_KEYBYTES)

    this.key = encryptionKey
    this.blockKey = isBlockKey ? encryptionKey : subKeys.subarray(0, sodium.crypto_stream_KEYBYTES)
    this.blindingKey = subKeys.subarray(sodium.crypto_stream_KEYBYTES)
    this.padding = 8
    this.compat = compat
    this.isBlockKey = isBlockKey

    if (!isBlockKey) {
      if (compat) sodium.crypto_generichash_batch(this.blockKey, [encryptionKey], hypercoreKey)
      else sodium.crypto_generichash_batch(this.blockKey, [BLOCK_ENCRYPTION, hypercoreKey, encryptionKey])
    }

    sodium.crypto_generichash(this.blindingKey, this.blockKey)
  }

  encrypt (index, block, fork) {
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    c.uint64.encode({ start: 0, end: 8, buffer: padding }, fork)
    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

    // Zero out any previous padding.
    nonce.fill(0, 8, 8 + padding.byteLength)

    // Blind the fork ID, possibly risking reusing the nonce on a reorg of the
    // Hypercore. This is fine as the blinding is best-effort and the latest
    // fork ID shared on replication anyway.
    sodium.crypto_stream_xor(
      padding,
      padding,
      nonce,
      this.blindingKey
    )

    nonce.set(padding, 8)

    // The combination of a (blinded) fork ID and a block index is unique for a
    // given Hypercore and is therefore a valid nonce for encrypting the block.
    sodium.crypto_stream_xor(
      block,
      block,
      nonce,
      this.blockKey
    )
  }

  decrypt (index, block) {
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

    nonce.set(padding, 8)

    // Decrypt the block using the blinded fork ID.
    sodium.crypto_stream_xor(
      block,
      block,
      nonce,
      this.blockKey
    )
  }
}

},{"./caps":35,"b4a":4,"compact-encoding":16,"sodium-universal":122}],34:[function(require,module,exports){
const b4a = require('b4a')

module.exports = class BlockStore {
  constructor (storage, tree) {
    this.storage = storage
    this.tree = tree
  }

  async get (i, tree) {
    if (!tree) tree = this.tree
    const [offset, size] = await tree.byteRange(2 * i)
    return this._read(offset, size)
  }

  async put (i, data, offset) {
    return this._write(offset, data)
  }

  putBatch (i, batch, offset) {
    if (batch.length === 0) return Promise.resolve()
    return this.put(i, batch.length === 1 ? batch[0] : b4a.concat(batch), offset)
  }

  clear (offset = 0, length = -1) {
    return new Promise((resolve, reject) => {
      if (length === -1) this.storage.truncate(offset, done)
      else this.storage.del(offset, length, done)

      function done (err) {
        if (err) reject(err)
        else resolve()
      }
    })
  }

  close () {
    return new Promise((resolve, reject) => {
      this.storage.close((err) => {
        if (err) reject(err)
        else resolve()
      })
    })
  }

  _read (offset, size) {
    return new Promise((resolve, reject) => {
      this.storage.read(offset, size, (err, data) => {
        if (err) reject(err)
        else resolve(data)
      })
    })
  }

  _write (offset, data) {
    return new Promise((resolve, reject) => {
      this.storage.write(offset, data, (err) => {
        if (err) reject(err)
        else resolve(offset + data.byteLength)
      })
    })
  }
}

},{"b4a":4}],35:[function(require,module,exports){
const crypto = require('hypercore-crypto')
const sodium = require('sodium-universal')
const b4a = require('b4a')
const c = require('compact-encoding')

// TODO: rename this to "crypto" and move everything hashing related etc in here
// Also lets move the tree stuff from hypercore-crypto here

const [
  TREE,
  REPLICATE_INITIATOR,
  REPLICATE_RESPONDER,
  MANIFEST,
  DEFAULT_NAMESPACE,
  BLOCK_ENCRYPTION
] = crypto.namespace('hypercore', 6)

exports.MANIFEST = MANIFEST
exports.DEFAULT_NAMESPACE = DEFAULT_NAMESPACE
exports.BLOCK_ENCRYPTION = BLOCK_ENCRYPTION

exports.replicate = function (isInitiator, key, handshakeHash) {
  const out = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, [isInitiator ? REPLICATE_INITIATOR : REPLICATE_RESPONDER, key], handshakeHash)
  return out
}

exports.treeSignable = function (namespace, hash, length, fork) {
  const state = { start: 0, end: 112, buffer: b4a.allocUnsafe(112) }
  c.raw.encode(state, TREE)
  c.raw.encode(state, namespace)
  c.raw.encode(state, hash)
  c.uint64.encode(state, length)
  c.uint64.encode(state, fork)
  return state.buffer
}

exports.treeSignableCompat = function (hash, length, fork, noHeader) {
  const end = noHeader ? 48 : 80
  const state = { start: 0, end, buffer: b4a.allocUnsafe(end) }
  if (!noHeader) c.raw.encode(state, TREE) // ultra legacy mode, kill in future major
  c.raw.encode(state, hash)
  c.uint64.encode(state, length)
  c.uint64.encode(state, fork)
  return state.buffer
}

},{"b4a":4,"compact-encoding":16,"hypercore-crypto":26,"sodium-universal":122}],36:[function(require,module,exports){
// Export the appropriate version of `quickbit-universal` as the plain import
// may resolve to an older version in some environments
let quickbit = require('quickbit-universal')
if (
  typeof quickbit.findFirst !== 'function' ||
  typeof quickbit.findLast !== 'function' ||
  typeof quickbit.clear !== 'function'
) {
  // This should always load the fallback from the locally installed version
  quickbit = require('quickbit-universal/fallback')
}
exports.quickbit = quickbit

},{"quickbit-universal":60,"quickbit-universal/fallback":60}],37:[function(require,module,exports){
const hypercoreCrypto = require('hypercore-crypto')
const b4a = require('b4a')
const Oplog = require('./oplog')
const BigHeader = require('./big-header')
const Mutex = require('./mutex')
const MerkleTree = require('./merkle-tree')
const BlockStore = require('./block-store')
const Bitfield = require('./bitfield')
const Info = require('./info')
const { BAD_ARGUMENT, STORAGE_EMPTY, STORAGE_CONFLICT, INVALID_SIGNATURE, INVALID_CHECKSUM } = require('hypercore-errors')
const m = require('./messages')
const { manifestHash, createVerifier, createManifest, defaultSignerManifest, isCompat } = require('./manifest')

module.exports = class Core {
  constructor (header, compat, crypto, oplog, bigHeader, tree, blocks, bitfield, verifier, legacy, onupdate, onconflict) {
    this.onupdate = onupdate
    this.onconflict = onconflict
    this.preupdate = null
    this.header = header
    this.compat = compat
    this.crypto = crypto
    this.oplog = oplog
    this.bigHeader = bigHeader
    this.tree = tree
    this.blocks = blocks
    this.bitfield = bitfield
    this.verifier = verifier
    this.truncating = 0
    this.updating = false
    this.closed = false

    this._manifestFlushed = !!header.manifest
    this._maxOplogSize = 65536
    this._autoFlush = 1
    this._verifies = null
    this._verifiesFlushed = null
    this._mutex = new Mutex()
    this._legacy = legacy
  }

  static async open (storage, opts = {}) {
    const oplogFile = storage('oplog')
    const treeFile = storage('tree')
    const bitfieldFile = storage('bitfield')
    const dataFile = storage('data')
    const headerFile = storage('header')

    try {
      return await this.resume(oplogFile, treeFile, bitfieldFile, dataFile, headerFile, opts)
    } catch (err) {
      await closeAll(oplogFile, treeFile, bitfieldFile, dataFile, headerFile)
      throw err
    }
  }

  static async resume (oplogFile, treeFile, bitfieldFile, dataFile, headerFile, opts) {
    let overwrite = opts.overwrite === true

    const force = opts.force === true
    const createIfMissing = opts.createIfMissing !== false
    const crypto = opts.crypto || hypercoreCrypto
    // kill this flag soon
    const legacy = !!opts.legacy

    const oplog = new Oplog(oplogFile, {
      headerEncoding: m.oplog.header,
      entryEncoding: m.oplog.entry,
      readonly: opts.readonly
    })

    // default to true for now if no manifest is provided
    let compat = opts.compat === true || (opts.compat !== false && !opts.manifest)

    let { header, entries } = await oplog.open()

    if (force && opts.key && header && !b4a.equals(header.key, opts.key)) {
      overwrite = true
    }

    const bigHeader = new BigHeader(headerFile)

    if (!header || overwrite) {
      if (!createIfMissing) {
        throw STORAGE_EMPTY('No Hypercore is stored here')
      }

      if (compat) {
        if (opts.key && opts.keyPair && !b4a.equals(opts.key, opts.keyPair.publicKey)) {
          throw BAD_ARGUMENT('Key must match publicKey when in compat mode')
        }
      }

      const keyPair = opts.keyPair || (opts.key ? null : crypto.keyPair())
      const defaultManifest = !opts.manifest && (!!opts.compat || !opts.key || !!(keyPair && b4a.equals(opts.key, keyPair.publicKey)))
      const manifest = defaultManifest ? defaultSignerManifest(opts.key || keyPair.publicKey) : createManifest(opts.manifest)

      header = {
        external: null,
        key: opts.key || (compat ? manifest.signer.publicKey : manifestHash(manifest)),
        manifest,
        keyPair,
        userData: [],
        tree: {
          fork: 0,
          length: 0,
          rootHash: null,
          signature: null
        },
        hints: {
          reorgs: [],
          contiguousLength: 0
        }
      }

      await flushHeader(oplog, bigHeader, header)
    } else if (header.external) {
      header = await bigHeader.load(header.external)
    }

    if (opts.manifest) {
      // if we provide a manifest and no key, verify that the stored key is the same
      if (!opts.key && !isValidManifest(header.key, createManifest(opts.manifest))) {
        throw STORAGE_CONFLICT('Manifest does not hash to provided key')
      }
    }

    if (opts.key && !b4a.equals(header.key, opts.key)) {
      throw STORAGE_CONFLICT('Another Hypercore is stored here')
    }

    // if we signalled compat, but already now this core isn't disable it
    if (compat && header.manifest && !isCompat(header.key, header.manifest)) {
      compat = false
    } else if (!compat && header.manifest && isCompat(header.key, header.manifest)) {
      compat = true
    }

    const tree = await MerkleTree.open(treeFile, { crypto, ...header.tree })
    const bitfield = await Bitfield.open(bitfieldFile, tree)
    const blocks = new BlockStore(dataFile, tree)

    if (overwrite) {
      await tree.clear()
      await blocks.clear()
      await bitfield.clear()
      entries = []
    } else if (bitfield.resumed && header.tree.length === 0) {
      // If this was an old bitfield, reset it since it loads based on disk size atm (TODO: change that)
      await bitfield.clear()
    }

    // compat from earlier version that do not store contig length
    if (header.hints.contiguousLength === 0) {
      while (bitfield.get(header.hints.contiguousLength)) header.hints.contiguousLength++
    }

    const verifier = header.manifest ? createVerifier(header.manifest, { compat: isCompat(header.key, header.manifest), crypto, legacy }) : null

    for (const e of entries) {
      if (e.userData) {
        updateUserData(header.userData, e.userData.key, e.userData.value)
      }

      if (e.treeNodes) {
        for (const node of e.treeNodes) {
          tree.addNode(node)
        }
      }

      if (e.bitfield) {
        bitfield.setRange(e.bitfield.start, e.bitfield.length, !e.bitfield.drop)
        updateContig(header, e.bitfield, bitfield)
      }

      if (e.treeUpgrade) {
        const batch = await tree.truncate(e.treeUpgrade.length, e.treeUpgrade.fork)
        batch.ancestors = e.treeUpgrade.ancestors
        batch.signature = e.treeUpgrade.signature
        addReorgHint(header.hints.reorgs, tree, batch)
        batch.commit()

        header.tree.length = tree.length
        header.tree.fork = tree.fork
        header.tree.rootHash = tree.hash()
        header.tree.signature = tree.signature
      }
    }

    return new this(header, compat, crypto, oplog, bigHeader, tree, blocks, bitfield, verifier, legacy, opts.onupdate || noop, opts.onconflict || noop)
  }

  setManifest (manifest, keyPair) {
    if (!manifest && b4a.equals(keyPair.publicKey, this.header.key)) manifest = defaultSignerManifest(this.header.key)
    if (!manifest) return

    const compat = isCompat(this.header.key, manifest)
    const verifier = createVerifier(manifest, { compat, crypto: this.crypto, legacy: this._legacy })

    this.compat = compat
    this.header.manifest = manifest
    this.verifier = verifier
    this._manifestFlushed = false

    this.onupdate(0b10000, null, null, null)
  }

  _shouldFlush () {
    // TODO: make something more fancy for auto flush mode (like fibonacci etc)
    if (--this._autoFlush <= 0 || this.oplog.byteLength >= this._maxOplogSize) {
      this._autoFlush = 4
      return true
    }

    if (!this._manifestFlushed && this.header.manifest) {
      this._manifestFlushed = true
      return true
    }

    return false
  }

  async copyFrom (src, signature, { length = src.tree.length } = {}) {
    await this._mutex.lock()

    try {
      await src._mutex.lock()
    } catch (err) {
      this._mutex.unlock()
      throw err
    }

    try {
      let pos = 0

      while (pos < length) {
        const segmentStart = maximumSegmentStart(pos, src.bitfield, this.bitfield)
        if (segmentStart >= length || segmentStart < 0) break

        const segmentEnd = Math.min(length, minimumSegmentEnd(segmentStart, src.bitfield, this.bitfield))

        const segment = []

        pos = segmentStart
        while (pos < segmentEnd) {
          const val = await src.blocks.get(pos++)
          segment.push(val)
        }

        const [offset] = await src.tree.byteRange(2 * segmentStart)
        await this.blocks.putBatch(segmentStart, segment, offset)

        this.bitfield.setRange(segmentStart, segmentEnd - segmentStart, true)

        pos = segmentEnd + 1
      }

      for (let i = 0; i < length * 2; i++) {
        const node = await src.tree.get(i, false)
        if (node === null) continue

        await this.tree.addNode(node)
      }

      await this.tree.flush()

      if (length > this.tree.length) {
        this.tree.fork = src.tree.fork
        this.tree.roots = [...src.tree.roots]
        this.tree.length = src.tree.length
        this.tree.byteLength = src.tree.byteLength

        if (length < this.tree.length) {
          const batch = await src.tree.truncate(length)
          this.tree.roots = [...batch.roots]
          this.tree.length = batch.length
          this.tree.byteLength = batch.byteLength
        }

        try {
          const batch = this.tree.batch()
          batch.signature = signature
          this._verifyBatchUpgrade(batch, this.header.manifest)
          this.tree.signature = signature
        } catch (err) {
          this.tree.signature = null
          // TODO: how to handle signature failure?
          throw err
        }

        this.header.tree.length = this.tree.length
        this.header.tree.rootHash = this.tree.hash()
        this.header.tree.signature = this.tree.signature
      }

      this.header.userData = src.header.userData.slice(0)
      this.header.hints.contiguousLength = Math.min(src.header.hints.contiguousLength, this.header.tree.length)

      await this._flushOplog()
    } finally {
      src._mutex.unlock()
      this._mutex.unlock()
    }
  }

  async flush () {
    await this._mutex.lock()
    try {
      this._manifestFlushed = true
      this._autoFlush = 4
      await this._flushOplog()
    } finally {
      this._mutex.unlock()
    }
  }

  async _flushOplog () {
    // TODO: the apis using this, actually do not need to wait for the bitfields, tree etc to flush
    // as their mutations are already stored in the oplog. We could potentially just run this in the
    // background. Might be easier to impl that where it is called instead and keep this one simple.
    await this.bitfield.flush()
    await this.tree.flush()

    return flushHeader(this.oplog, this.bigHeader, this.header)
  }

  _appendBlocks (values) {
    return this.blocks.putBatch(this.tree.length, values, this.tree.byteLength)
  }

  async _writeBlock (batch, index, value) {
    const byteOffset = await batch.byteOffset(index * 2)
    await this.blocks.put(index, value, byteOffset)
  }

  async userData (key, value, flush) {
    // TODO: each oplog append can set user data, so we should have a way
    // to just hitch a ride on one of the other ongoing appends?
    await this._mutex.lock()

    try {
      let empty = true

      for (const u of this.header.userData) {
        if (u.key !== key) continue
        if (value && b4a.equals(u.value, value)) return
        empty = false
        break
      }

      if (empty && !value) return

      const entry = {
        userData: { key, value },
        treeNodes: null,
        treeUpgrade: null,
        bitfield: null
      }

      await this.oplog.append([entry], false)

      updateUserData(this.header.userData, key, value)

      if (this._shouldFlush() || flush) await this._flushOplog()
    } finally {
      this._mutex.unlock()
    }
  }

  async truncate (length, fork, { signature, keyPair = this.header.keyPair } = {}) {
    this.truncating++
    await this._mutex.lock()

    // upsert compat manifest
    if (this.verifier === null && keyPair) this.setManifest(null, keyPair)

    try {
      const batch = await this.tree.truncate(length, fork)
      if (length > 0) batch.signature = signature || this.verifier.sign(batch, keyPair)
      await this._truncate(batch, null)
    } finally {
      this.truncating--
      this._mutex.unlock()
    }
  }

  async clear (start, end, cleared) {
    await this._mutex.lock()

    try {
      const entry = {
        userData: null,
        treeNodes: null,
        treeUpgrade: null,
        bitfield: {
          start,
          length: end - start,
          drop: true
        }
      }

      await this.oplog.append([entry], false)

      this.bitfield.setRange(start, end - start, false)

      if (start < this.header.hints.contiguousLength) {
        this.header.hints.contiguousLength = start
      }

      start = this.bitfield.lastSet(start) + 1
      end = this.bitfield.firstSet(end)

      if (end === -1) end = this.tree.length
      if (start >= end || start >= this.tree.length) return

      const offset = await this.tree.byteOffset(start * 2)
      const endOffset = await this.tree.byteOffset(end * 2)
      const length = endOffset - offset

      const before = cleared ? await Info.bytesUsed(this.blocks.storage) : null

      await this.blocks.clear(offset, length)

      const after = cleared ? await Info.bytesUsed(this.blocks.storage) : null

      if (cleared) cleared.blocks = Math.max(before - after, 0)

      this.onupdate(0, entry.bitfield, null, null)

      if (this._shouldFlush()) await this._flushOplog()
    } finally {
      this._mutex.unlock()
    }
  }

  async purge () {
    return new Promise((resolve, reject) => {
      let missing = 4
      let error = null

      this.oplog.storage.unlink(done)
      this.tree.storage.unlink(done)
      this.bitfield.storage.unlink(done)
      this.blocks.storage.unlink(done)

      function done (err) {
        if (err) error = err
        if (--missing) return
        if (error) reject(error)
        else resolve()
      }
    })
  }

  async insertBatch (batch, values, { signature, keyPair = this.header.keyPair, pending = false, treeLength = batch.treeLength } = {}) {
    await this._mutex.lock()

    try {
      // upsert compat manifest
      if (this.verifier === null && keyPair) this.setManifest(null, keyPair)

      if (this.tree.fork !== batch.fork) return null

      if (this.tree.length > batch.treeLength) {
        if (this.tree.length > batch.length) return null // TODO: partial commit in the future if possible

        for (const root of this.tree.roots) {
          const batchRoot = await batch.get(root.index)
          if (batchRoot.size !== root.size || !b4a.equals(batchRoot.hash, root.hash)) {
            return null
          }
        }
      }

      const adding = batch.length - treeLength

      batch.upgraded = !pending && batch.length > this.tree.length
      batch.treeLength = this.tree.length
      batch.ancestors = this.tree.length
      if (batch.upgraded && !pending) batch.signature = signature || this.verifier.sign(batch, keyPair)

      let byteOffset = batch.byteLength
      for (let i = 0; i < adding; i++) byteOffset -= values[i].byteLength

      if (pending === true) batch.upgraded = false

      const entry = {
        userData: null,
        treeNodes: batch.nodes,
        treeUpgrade: batch.upgraded ? batch : null,
        bitfield: {
          drop: false,
          start: treeLength,
          length: adding
        }
      }

      await this.blocks.putBatch(treeLength, adding > values.length ? values.slice(0, adding) : values, byteOffset)
      await this.oplog.append([entry], false)

      this.bitfield.setRange(entry.bitfield.start, entry.bitfield.length, true)
      batch.commit()

      if (batch.upgraded) {
        this.header.tree.length = batch.length
        this.header.tree.rootHash = batch.hash()
        this.header.tree.signature = batch.signature
      }

      const status = (batch.upgraded ? 0b0001 : 0) | updateContig(this.header, entry.bitfield, this.bitfield)
      if (!pending) {
        // we already commit this, and now we signed it, so tell others
        if (entry.treeUpgrade && treeLength > batch.treeLength) {
          entry.bitfield.start = batch.treeLength
          entry.bitfield.length = treeLength - batch.treeLength
        }

        this.onupdate(status, entry.bitfield, null, null)
      }

      if (this._shouldFlush()) await this._flushOplog()
    } finally {
      this._mutex.unlock()
    }

    return { length: batch.length, byteLength: batch.byteLength }
  }

  async append (values, { signature, keyPair = this.header.keyPair, preappend } = {}) {
    await this._mutex.lock()

    try {
      // upsert compat manifest
      if (this.verifier === null && keyPair) this.setManifest(null, keyPair)

      if (preappend) await preappend(values)

      if (!values.length) {
        return { length: this.tree.length, byteLength: this.tree.byteLength }
      }

      const batch = this.tree.batch()
      for (const val of values) batch.append(val)

      batch.signature = signature || this.verifier.sign(batch, keyPair)

      const entry = {
        userData: null,
        treeNodes: batch.nodes,
        treeUpgrade: batch,
        bitfield: {
          drop: false,
          start: batch.ancestors,
          length: values.length
        }
      }

      const byteLength = await this._appendBlocks(values)

      await this.oplog.append([entry], false)

      this.bitfield.setRange(batch.ancestors, batch.length - batch.ancestors, true)
      batch.commit()

      this.header.tree.length = batch.length
      this.header.tree.rootHash = batch.hash()
      this.header.tree.signature = batch.signature

      const status = 0b0001 | updateContig(this.header, entry.bitfield, this.bitfield)
      this.onupdate(status, entry.bitfield, null, null)

      if (this._shouldFlush()) await this._flushOplog()

      return { length: batch.length, byteLength }
    } finally {
      this._mutex.unlock()
    }
  }

  _verifyBatchUpgrade (batch, manifest) {
    if (!this.header.manifest) {
      if (!manifest && this.compat) manifest = defaultSignerManifest(this.header.key)

      if (!manifest || !(isValidManifest(this.header.key, manifest) || (this.compat && isCompat(this.header.key, manifest)))) {
        throw INVALID_SIGNATURE('Proof contains an invalid manifest') // TODO: proper error type
      }
    }

    const verifier = this.verifier || createVerifier(manifest, { compat: isCompat(this.header.key, manifest), crypto: this.crypto, legacy: this._legacy })

    if (!verifier.verify(batch, batch.signature)) {
      throw INVALID_SIGNATURE('Proof contains an invalid signature')
    }

    if (!this.header.manifest) {
      this.compat = isCompat(this.header.key, manifest)
      this.header.manifest = manifest
      this.verifier = verifier
      this.onupdate(0b10000, null, null, null)
    }
  }

  async _verifyExclusive ({ batch, bitfield, value, manifest, from }) {
    this._verifyBatchUpgrade(batch, manifest)

    await this._mutex.lock()

    try {
      if (!batch.commitable()) return false
      this.updating = true

      const entry = {
        userData: null,
        treeNodes: batch.nodes,
        treeUpgrade: batch,
        bitfield
      }

      if (this.preupdate !== null) await this.preupdate(batch, this.header.key)
      if (bitfield) await this._writeBlock(batch, bitfield.start, value)

      await this.oplog.append([entry], false)

      let status = 0b0001

      if (bitfield) {
        this.bitfield.set(bitfield.start, true)
        status |= updateContig(this.header, bitfield, this.bitfield)
      }

      batch.commit()

      this.header.tree.fork = batch.fork
      this.header.tree.length = batch.length
      this.header.tree.rootHash = batch.hash()
      this.header.tree.signature = batch.signature

      this.onupdate(status, bitfield, value, from)

      if (this._shouldFlush()) await this._flushOplog()
    } finally {
      this.updating = false
      this._mutex.unlock()
    }

    return true
  }

  async _verifyShared () {
    if (!this._verifies.length) return false

    await this._mutex.lock()

    const verifies = this._verifies
    this._verifies = null
    this._verified = null

    try {
      const entries = []

      for (const { batch, bitfield, value } of verifies) {
        if (!batch.commitable()) continue

        if (bitfield) {
          await this._writeBlock(batch, bitfield.start, value)
        }

        entries.push({
          userData: null,
          treeNodes: batch.nodes,
          treeUpgrade: null,
          bitfield
        })
      }

      await this.oplog.append(entries, false)

      for (let i = 0; i < verifies.length; i++) {
        const { batch, bitfield, value, manifest, from } = verifies[i]

        if (!batch.commitable()) {
          verifies[i] = null // signal that we cannot commit this one
          continue
        }

        let status = 0

        if (bitfield) {
          this.bitfield.set(bitfield.start, true)
          status = updateContig(this.header, bitfield, this.bitfield)
        }

        // if we got a manifest AND its strictly a non compat one, lets store it
        if (manifest && this.header.manifest === null) {
          if (!isValidManifest(this.header.key, manifest)) throw INVALID_CHECKSUM('Manifest hash does not match')
          this.setManifest(manifest, null)
        }

        batch.commit()

        this.onupdate(status, bitfield, value, from)
      }

      if (this._shouldFlush()) await this._flushOplog()
    } finally {
      this._mutex.unlock()
    }

    return verifies[0] !== null
  }

  async checkConflict (proof, from) {
    if (this.tree.length < proof.upgrade.length || proof.fork !== this.tree.fork) {
      // out of date this proof - ignore for now
      return false
    }

    const batch = this.tree.verifyFullyRemote(proof)

    try {
      this._verifyBatchUpgrade(batch, proof.manifest)
    } catch {
      return true
    }

    const remoteTreeHash = this.crypto.tree(proof.upgrade.nodes)
    const localTreeHash = this.crypto.tree(await this.tree.getRoots(proof.upgrade.length))

    if (b4a.equals(localTreeHash, remoteTreeHash)) return false

    await this.onconflict(proof)
    return true
  }

  async verifyReorg (proof) {
    const batch = await this.tree.reorg(proof)

    this._verifyBatchUpgrade(batch, proof.manifest)

    return batch
  }

  async verify (proof, from) {
    // We cannot apply "other forks" atm.
    // We should probably still try and they are likely super similar for non upgrades
    // but this is easy atm (and the above layer will just retry)
    if (proof.fork !== this.tree.fork) return false

    const batch = await this.tree.verify(proof)
    if (!batch.commitable()) return false

    const value = (proof.block && proof.block.value) || null
    const op = {
      batch,
      bitfield: value && { drop: false, start: proof.block.index, length: 1 },
      value,
      manifest: proof.manifest,
      from
    }

    if (batch.upgraded) return this._verifyExclusive(op)

    if (this._verifies !== null) {
      const verifies = this._verifies
      const i = verifies.push(op)
      await this._verified
      return verifies[i] !== null
    }

    this._verifies = [op]
    this._verified = this._verifyShared()
    return this._verified
  }

  async reorg (batch, from) {
    if (!batch.commitable()) return false

    this.truncating++
    await this._mutex.lock()

    try {
      if (!batch.commitable()) return false
      await this._truncate(batch, from)
    } finally {
      this.truncating--
      this._mutex.unlock()
    }

    return true
  }

  async _truncate (batch, from) {
    const entry = {
      userData: null,
      treeNodes: batch.nodes,
      treeUpgrade: batch,
      bitfield: {
        drop: true,
        start: batch.ancestors,
        length: this.tree.length - batch.ancestors
      }
    }

    await this.oplog.append([entry], false)

    this.bitfield.setRange(batch.ancestors, this.tree.length - batch.ancestors, false)
    addReorgHint(this.header.hints.reorgs, this.tree, batch)
    batch.commit()

    const contigStatus = updateContig(this.header, entry.bitfield, this.bitfield)
    const status = ((batch.length > batch.ancestors) ? 0b0011 : 0b0010) | contigStatus

    this.header.tree.fork = batch.fork
    this.header.tree.length = batch.length
    this.header.tree.rootHash = batch.hash()
    this.header.tree.signature = batch.signature

    this.onupdate(status, entry.bitfield, null, from)

    // TODO: there is a bug in the merkle tree atm where it cannot handle unflushed
    // truncates if we append or download anything after the truncation point later on
    // This is because tree.get checks the truncated flag. We should fix this so we can do
    // the later flush here as well
    // if (this._shouldFlush()) await this._flushOplog()
    await this._flushOplog()
  }

  async close () {
    this.closed = true
    await this._mutex.destroy()
    await Promise.allSettled([
      this.oplog.close(),
      this.bitfield.close(),
      this.tree.close(),
      this.blocks.close(),
      this.bigHeader.close()
    ])
  }
}

function updateContig (header, upd, bitfield) {
  const end = upd.start + upd.length

  let c = header.hints.contiguousLength

  if (upd.drop) {
    // If we dropped a block in the current contig range, "downgrade" it
    if (c <= end && c > upd.start) {
      c = upd.start
    }
  } else {
    if (c <= end && c >= upd.start) {
      c = end
      while (bitfield.get(c)) c++
    }
  }

  if (c === header.hints.contiguousLength) {
    return 0b0000
  }

  if (c > header.hints.contiguousLength) {
    header.hints.contiguousLength = c
    return 0b0100
  }

  header.hints.contiguousLength = c
  return 0b1000
}

function isValidManifest (key, manifest) {
  return b4a.equals(key, manifestHash(manifest))
}

function addReorgHint (list, tree, batch) {
  if (tree.length === 0 || tree.fork === batch.fork) return

  while (list.length >= 4) list.shift() // 4 here is arbitrary, just want it to be small (hints only)
  while (list.length > 0) {
    if (list[list.length - 1].ancestors > batch.ancestors) list.pop()
    else break
  }

  list.push({ from: tree.fork, to: batch.fork, ancestors: batch.ancestors })
}

function updateUserData (list, key, value) {
  for (let i = 0; i < list.length; i++) {
    if (list[i].key === key) {
      if (value) list[i].value = value
      else list.splice(i, 1)
      return
    }
  }
  if (value) list.push({ key, value })
}

function closeAll (...storages) {
  let missing = 1
  let error = null

  return new Promise((resolve, reject) => {
    for (const s of storages) {
      missing++
      s.close(done)
    }

    done(null)

    function done (err) {
      if (err) error = err
      if (--missing) return
      if (error) reject(error)
      else resolve()
    }
  })
}

async function flushHeader (oplog, bigHeader, header) {
  if (header.external) {
    await bigHeader.flush(header)
  }

  try {
    await oplog.flush(header)
  } catch (err) {
    if (err.code !== 'OPLOG_HEADER_OVERFLOW') throw err
    await bigHeader.flush(header)
    await oplog.flush(header)
  }
}

function noop () {}

function maximumSegmentStart (start, src, dst) {
  while (true) {
    const a = src.firstSet(start)
    const b = dst.firstUnset(start)

    if (a === -1) return -1
    if (b === -1) return a

    // if dst has the segment, restart
    if (a < b) {
      start = b
      continue
    }

    return a
  }
}

function minimumSegmentEnd (start, src, dst) {
  const a = src.firstUnset(start)
  const b = dst.firstSet(start)

  if (a === -1) return -1
  if (b === -1) return a
  return a < b ? a : b
}

},{"./big-header":31,"./bitfield":32,"./block-store":34,"./info":39,"./manifest":40,"./merkle-tree":41,"./messages":42,"./mutex":44,"./oplog":45,"b4a":4,"hypercore-crypto":26,"hypercore-errors":27}],38:[function(require,module,exports){
module.exports = class Download {
  constructor (req) {
    this.req = req
  }

  async done () {
    return (await this.req).promise
  }

  /**
   * Deprecated. Use `range.done()`.
   */
  downloaded () {
    return this.done()
  }

  destroy () {
    this.req.then(req => req.context && req.context.detach(req), noop)
  }
}

function noop () {}

},{}],39:[function(require,module,exports){
module.exports = class Info {
  constructor (opts = {}) {
    this.key = opts.key
    this.discoveryKey = opts.discoveryKey
    this.length = opts.length || 0
    this.contiguousLength = opts.contiguousLength || 0
    this.byteLength = opts.byteLength || 0
    this.fork = opts.fork || 0
    this.padding = opts.padding || 0
    this.storage = opts.storage || null
  }

  static async from (session, opts = {}) {
    return new Info({
      key: session.key,
      discoveryKey: session.discoveryKey,
      length: session.length,
      contiguousLength: session.contiguousLength,
      byteLength: session.byteLength,
      fork: session.fork,
      padding: session.padding,
      storage: opts.storage ? await this.storage(session) : null
    })
  }

  static async storage (session) {
    const { oplog, tree, blocks, bitfield } = session.core
    try {
      return {
        oplog: await Info.bytesUsed(oplog.storage),
        tree: await Info.bytesUsed(tree.storage),
        blocks: await Info.bytesUsed(blocks.storage),
        bitfield: await Info.bytesUsed(bitfield.storage)
      }
    } catch {
      return null
    }
  }

  static bytesUsed (file) {
    return new Promise((resolve, reject) => {
      file.stat((err, st) => {
        if (err) {
          resolve(0) // prob just file not found (TODO, improve)
        } else if (typeof st.blocks !== 'number') {
          reject(new Error('cannot determine bytes used'))
        } else {
          resolve(st.blocks * 512)
        }
      })
    })
  }
}

},{}],40:[function(require,module,exports){
const defaultCrypto = require('hypercore-crypto')
const b4a = require('b4a')
const c = require('compact-encoding')
const { BAD_ARGUMENT } = require('hypercore-errors')

const m = require('./messages')
const multisig = require('./multisig')
const caps = require('./caps')

module.exports = {
  manifestHash,
  isCompat,
  defaultSignerManifest,
  createManifest,
  createVerifier
}

class StaticVerifier {
  constructor (treeHash) {
    this.treeHash = treeHash
  }

  sign () {
    return null
  }

  verify (batch, signature) {
    return b4a.equals(batch.hash(), this.treeHash)
  }
}

class CompatVerifier {
  constructor (crypto, signer, legacy) {
    validateSigner(signer)

    this.legacy = legacy
    this.crypto = crypto
    this.publicKey = signer.publicKey
  }

  sign (batch, keyPair) {
    if (!keyPair || !keyPair.secretKey) throw BAD_ARGUMENT('No signer was passed')
    return this.crypto.sign(batch.signableCompat(this.legacy), keyPair.secretKey)
  }

  verify (batch, signature) {
    if (!signature) return false
    return this.crypto.verify(batch.signableCompat(this.legacy), signature, this.publicKey)
  }
}

class SingleVerifier {
  constructor (crypto, signer) {
    validateSigner(signer)

    this.crypto = crypto
    this.publicKey = signer.publicKey
    this.namespace = signer.namespace
  }

  sign (batch, keyPair) {
    if (!keyPair || !keyPair.secretKey) throw BAD_ARGUMENT('No signer was passed')
    return this.crypto.sign(batch.signable(this.namespace), keyPair.secretKey)
  }

  verify (batch, signature) {
    if (!signature) return false
    return this.crypto.verify(batch.signable(this.namespace), signature, this.publicKey)
  }
}

class MultiVerifier {
  constructor (crypto, multipleSigners) {
    this.signers = multipleSigners.signers
    this.quorum = multipleSigners.quorum
    this.allowPatched = multipleSigners.allowPatched
    this.verifiers = this.signers.map(s => new SingleVerifier(crypto, s))

    if (this.verifiers.length < this.quorum || (this.quorum === 0)) throw BAD_ARGUMENT('Invalid quorum')
  }

  sign () {
    throw BAD_ARGUMENT('Multi signature must be provided')
  }

  verify (batch, signature) {
    if (!signature) return false

    const inputs = multisig.inflate(signature)

    if (inputs.length < this.quorum) return false

    const tried = new Uint8Array(this.verifiers.length)

    for (let i = 0; i < this.quorum; i++) {
      const inp = inputs[i]

      let tree = batch

      if (inp.patch) {
        if (!this.allowPatched) return false

        tree = batch.clone()
        const proof = { fork: tree.fork, block: null, hash: null, seek: null, upgrade: inp.patch, manifest: null }

        try {
          if (!tree.verifyUpgrade(proof)) return false
        } catch {
          return false
        }
      }

      if (inp.signer >= this.verifiers.length || tried[inp.signer]) return false
      tried[inp.signer] = 1

      if (!this.verifiers[inp.signer].verify(tree, inp.signature)) return false
    }

    return true
  }
}

function createVerifier (manifest, { compat = false, crypto = defaultCrypto, legacy = false } = {}) {
  if (compat && manifest.signer) {
    return new CompatVerifier(crypto, manifest.signer, legacy)
  }

  if (manifest.static) {
    return new StaticVerifier(manifest.static)
  }

  if (manifest.signer) {
    return new SingleVerifier(crypto, manifest.signer)
  }

  if (manifest.multipleSigners) {
    return new MultiVerifier(crypto, manifest.multipleSigners)
  }

  throw BAD_ARGUMENT('No signer was provided')
}

function createManifest (inp) {
  if (!inp) return null

  const manifest = {
    hash: 'blake2b',
    static: null,
    signer: null,
    multipleSigners: null
  }

  if (inp.hash && inp.hash !== 'blake2b') throw BAD_ARGUMENT('Only Blake2b hashes are supported')

  if (inp.static) {
    if (!(b4a.isBuffer(inp.static) && inp.static.byteLength === 32)) throw BAD_ARGUMENT('Invalid static manifest')
    manifest.static = inp.static
    return manifest
  }

  if (inp.signer) {
    manifest.signer = parseSigner(inp.signer)
    return manifest
  }

  if (inp.multipleSigners) {
    manifest.multipleSigners = parseMultipleSigners(inp.multipleSigners)
    return manifest
  }

  throw BAD_ARGUMENT('No signer was provided')
}

function parseMultipleSigners (m) {
  if (m.signers.length < m.quorum || !(m.quorum > 0)) throw BAD_ARGUMENT('Invalid quorum')

  return {
    allowPatched: !!m.allowPatched,
    quorum: m.quorum,
    signers: m.signers.map(parseSigner)
  }
}

function parseSigner (signer) {
  validateSigner(signer)
  return {
    signature: 'ed25519',
    namespace: signer.namespace || caps.DEFAULT_NAMESPACE,
    publicKey: signer.publicKey
  }
}

function validateSigner (signer) {
  if (!signer || !signer.publicKey) throw BAD_ARGUMENT('Signer missing public key')
  if (signer.signature && signer.signature !== 'ed25519') throw BAD_ARGUMENT('Only Ed25519 signatures are supported')
}

function defaultSignerManifest (publicKey) {
  return {
    hash: 'blake2b',
    static: null,
    signer: {
      signature: 'ed25519',
      namespace: caps.DEFAULT_NAMESPACE,
      publicKey
    },
    multipleSigners: null
  }
}

function manifestHash (manifest) {
  const state = { start: 0, end: 32, buffer: null }
  m.manifest.preencode(state, manifest)
  state.buffer = b4a.allocUnsafe(state.end)
  c.raw.encode(state, caps.MANIFEST)
  m.manifest.encode(state, manifest)
  return defaultCrypto.hash(state.buffer)
}

function isCompat (key, manifest) {
  return !!(manifest && manifest.signer && b4a.equals(key, manifest.signer.publicKey))
}

},{"./caps":35,"./messages":42,"./multisig":43,"b4a":4,"compact-encoding":16,"hypercore-crypto":26,"hypercore-errors":27}],41:[function(require,module,exports){
const flat = require('flat-tree')
const crypto = require('hypercore-crypto')
const c = require('compact-encoding')
const Xache = require('xache')
const b4a = require('b4a')
const caps = require('./caps')
const { INVALID_PROOF, INVALID_CHECKSUM, INVALID_OPERATION, BAD_ARGUMENT } = require('hypercore-errors')

const BLANK_HASH = b4a.alloc(32)
const OLD_TREE = b4a.from([5, 2, 87, 2, 0, 0, 40, 7, 66, 76, 65, 75, 69, 50, 98])
const TREE_CACHE = 128 // speeds up linear scans by A LOT

class NodeQueue {
  constructor (nodes, extra = null) {
    this.i = 0
    this.nodes = nodes
    this.extra = extra
    this.length = nodes.length + (this.extra === null ? 0 : 1)
  }

  shift (index) {
    if (this.extra !== null && this.extra.index === index) {
      const node = this.extra
      this.extra = null
      this.length--
      return node
    }

    if (this.i >= this.nodes.length) {
      throw INVALID_OPERATION('Expected node ' + index + ', got (nil)')
    }

    const node = this.nodes[this.i++]
    if (node.index !== index) {
      throw INVALID_OPERATION('Expected node ' + index + ', got node ' + node.index)
    }

    this.length--
    return node
  }
}

class MerkleTreeBatch {
  constructor (tree) {
    this.fork = tree.fork
    this.roots = [...tree.roots]
    this.length = tree.length
    this.ancestors = tree.length
    this.byteLength = tree.byteLength
    this.signature = null
    this.hashCached = null

    this.treeLength = tree.length
    this.treeFork = tree.fork
    this.tree = tree
    this.nodes = []
    this.upgraded = false
  }

  clone () {
    const b = new MerkleTreeBatch(this.tree)

    b.fork = this.fork
    b.roots = [...this.roots]
    b.length = this.length
    b.byteLength = this.byteLength
    b.signature = this.signature
    b.treeLength = this.treeLength
    b.treeFork = this.treeFork
    b.tree = this.tree
    b.nodes = [...this.nodes]
    b.upgraded = this.upgraded

    return b
  }

  hash () {
    if (this.hashCached === null) this.hashCached = this.tree.crypto.tree(this.roots)
    return this.hashCached
  }

  signable (namespace) {
    return caps.treeSignable(namespace, this.hash(), this.length, this.fork)
  }

  signableCompat (noHeader) {
    return caps.treeSignableCompat(this.hash(), this.length, this.fork, noHeader)
  }

  get (index, error) {
    if (index >= this.length * 2) {
      return null
    }

    for (const n of this.nodes) {
      if (n.index === index) return n
    }

    return this.tree.get(index, error)
  }

  proof ({ block, hash, seek, upgrade }) {
    return generateProof(this, block, hash, seek, upgrade)
  }

  verifyUpgrade (proof) {
    const unverified = verifyTree(proof, this.tree.crypto, this.nodes)

    if (!proof.upgrade) throw INVALID_OPERATION('Expected upgrade proof')

    return verifyUpgrade(proof, unverified, this)
  }

  append (buf) {
    const head = this.length * 2
    const ite = flat.iterator(head)
    const node = blockNode(this.tree.crypto, head, buf)

    this.appendRoot(node, ite)
  }

  appendRoot (node, ite) {
    this.hashCached = null
    this.upgraded = true
    this.length += ite.factor / 2
    this.byteLength += node.size
    this.roots.push(node)
    this.nodes.push(node)

    while (this.roots.length > 1) {
      const a = this.roots[this.roots.length - 1]
      const b = this.roots[this.roots.length - 2]

      // TODO: just have a peek sibling instead? (pretty sure it's always the left sib as well)
      if (ite.sibling() !== b.index) {
        ite.sibling() // unset so it always points to last root
        break
      }

      const node = parentNode(this.tree.crypto, ite.parent(), a, b)
      this.nodes.push(node)
      this.roots.pop()
      this.roots.pop()
      this.roots.push(node)
    }
  }

  commitable () {
    return this.treeFork === this.tree.fork && (
      this.upgraded
        ? this.treeLength === this.tree.length
        : this.treeLength <= this.tree.length
    )
  }

  commit () {
    if (!this.commitable()) throw INVALID_OPERATION('Tree was modified during batch, refusing to commit')

    if (this.upgraded) this._commitUpgrade()

    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i]
      this.tree.unflushed.set(node.index, node)
    }
  }

  _commitUpgrade () {
    // TODO: If easy to detect, we should refuse an trunc+append here without a fork id
    // change. Will only happen on user error so mostly to prevent that.

    if (this.ancestors < this.treeLength) {
      if (this.ancestors > 0) {
        const head = 2 * this.ancestors
        const ite = flat.iterator(head - 2)

        while (true) {
          if (ite.contains(head) && ite.index < head) {
            this.tree.unflushed.set(ite.index, blankNode(ite.index))
          }
          if (ite.offset === 0) break
          ite.parent()
        }
      }

      this.tree.truncateTo = this.tree.truncated
        ? Math.min(this.tree.truncateTo, this.ancestors)
        : this.ancestors

      this.tree.truncated = true
      this.tree.cache = new Xache({ maxSize: this.tree.cache.maxSize })
      truncateMap(this.tree.unflushed, this.ancestors)
      if (this.tree.flushing !== null) truncateMap(this.tree.flushing, this.ancestors)
    }

    this.tree.roots = this.roots
    this.tree.length = this.length
    this.tree.byteLength = this.byteLength
    this.tree.fork = this.fork
    this.tree.signature = this.signature
  }

  seek (bytes, padding) {
    return new ByteSeeker(this, bytes, padding)
  }

  byteRange (index) {
    return getByteRange(this, index)
  }

  byteOffset (index) {
    if (index === 2 * this.tree.length) return this.tree.byteLength
    return getByteOffset(this, index)
  }
}

class ReorgBatch extends MerkleTreeBatch {
  constructor (tree) {
    super(tree)
    this.roots = []
    this.length = 0
    this.byteLength = 0
    this.diff = null
    this.ancestors = 0
    // We set upgraded because reorgs are signed so hit will
    // hit the same code paths (like the treeLength check in commit)
    this.upgraded = true
    this.want = {
      nodes: 0,
      start: 0,
      end: 0
    }
  }

  get finished () {
    return this.want === null
  }

  update (proof) {
    if (this.want === null) return true

    const nodes = []
    const root = verifyTree(proof, this.tree.crypto, nodes)

    if (root === null || !b4a.equals(root.hash, this.diff.hash)) return false

    this.nodes.push(...nodes)
    return this._update(nodes)
  }

  async _update (nodes) {
    const n = new Map()
    for (const node of nodes) n.set(node.index, node)

    let diff = null
    const ite = flat.iterator(this.diff.index)
    const startingDiff = this.diff

    while ((ite.index & 1) !== 0) {
      const left = n.get(ite.leftChild())
      if (!left) break

      const existing = await this.tree.get(left.index, false)
      if (!existing || !b4a.equals(existing.hash, left.hash)) {
        diff = left
      } else {
        diff = n.get(ite.sibling())
      }
    }

    if ((this.diff.index & 1) === 0) return true
    if (diff === null) return false
    if (startingDiff !== this.diff) return false

    return this._updateDiffRoot(diff)
  }

  _updateDiffRoot (diff) {
    if (this.want === null) return true

    const spans = flat.spans(diff.index)
    const start = spans[0] / 2
    const end = Math.min(this.treeLength, spans[1] / 2 + 1)
    const len = end - start

    this.ancestors = start
    this.diff = diff

    if ((diff.index & 1) === 0 || this.want.start >= this.treeLength || len <= 0) {
      this.want = null
      return true
    }

    this.want.start = start
    this.want.end = end
    this.want.nodes = log2(spans[1] - spans[0] + 2) - 1

    return false
  }
}

class ByteSeeker {
  constructor (tree, bytes, padding = 0) {
    this.tree = tree
    this.bytes = bytes
    this.padding = padding

    const size = tree.byteLength - (tree.length * padding)

    this.start = bytes >= size ? tree.length : 0
    this.end = bytes < size ? tree.length : 0
  }

  async _seek (bytes) {
    if (!bytes) return [0, 0]

    for (const node of this.tree.roots) { // all async ticks happen once we find the root so safe
      const size = getUnpaddedSize(node, this.padding, null)

      if (bytes === size) return [flat.rightSpan(node.index) + 2, 0]
      if (bytes > size) {
        bytes -= size
        continue
      }

      const ite = flat.iterator(node.index)

      while ((ite.index & 1) !== 0) {
        const l = await this.tree.get(ite.leftChild(), false)

        if (l) {
          const size = getUnpaddedSize(l, this.padding, ite)

          if (size === bytes) return [ite.rightSpan() + 2, 0]
          if (size > bytes) continue
          bytes -= size
          ite.sibling()
        } else {
          ite.parent()
          return [ite.index, bytes]
        }
      }

      return [ite.index, bytes]
    }

    return null
  }

  async update () { // TODO: combine _seek and this, much simpler
    const res = await this._seek(this.bytes)
    if (!res) return null
    if ((res[0] & 1) === 0) return [res[0] / 2, res[1]]

    const span = flat.spans(res[0])
    this.start = span[0] / 2
    this.end = span[1] / 2 + 1

    return null
  }
}

module.exports = class MerkleTree {
  constructor (storage, roots, fork, signature) {
    this.crypto = crypto
    this.fork = fork
    this.roots = roots
    this.length = roots.length ? totalSpan(roots) / 2 : 0
    this.byteLength = totalSize(roots)
    this.signature = signature

    this.storage = storage
    this.unflushed = new Map()
    this.cache = new Xache({ maxSize: TREE_CACHE })
    this.flushing = null
    this.truncated = false
    this.truncateTo = 0
  }

  addNode (node) {
    if (node.size === 0 && b4a.equals(node.hash, BLANK_HASH)) node = blankNode(node.index)
    this.unflushed.set(node.index, node)
  }

  batch () {
    return new MerkleTreeBatch(this)
  }

  async restoreBatch (length) {
    const batch = new MerkleTreeBatch(this)
    if (length === this.length) return batch

    const roots = await this.getRoots(length)

    batch.roots = roots
    batch.length = length
    batch.byteLength = 0
    batch.ancestors = length

    for (const node of roots) batch.byteLength += node.size

    return batch
  }

  seek (bytes, padding) {
    return new ByteSeeker(this, bytes, padding)
  }

  hash () {
    return this.crypto.tree(this.roots)
  }

  signable (namespace) {
    return caps.treeSignable(namespace, this.hash(), this.length, this.fork)
  }

  getRoots (length) {
    const indexes = flat.fullRoots(2 * length)
    const roots = new Array(indexes.length)

    for (let i = 0; i < indexes.length; i++) {
      roots[i] = this.get(indexes[i], true)
    }

    return Promise.all(roots)
  }

  async upgradeable (length) {
    const indexes = flat.fullRoots(2 * length)
    const roots = new Array(indexes.length)

    for (let i = 0; i < indexes.length; i++) {
      roots[i] = this.get(indexes[i], false)
    }

    for (const node of await Promise.all(roots)) {
      if (node === null) return false
    }

    return true
  }

  get (index, error = true) {
    const c = this.cache.get(index)
    if (c) return c

    let node = this.unflushed.get(index)

    if (this.flushing !== null && node === undefined) {
      node = this.flushing.get(index)
    }

    // TODO: test this
    if (this.truncated && node !== undefined && node.index >= 2 * this.truncateTo) {
      node = blankNode(index)
    }

    if (node !== undefined) {
      if (node.hash === BLANK_HASH) {
        if (error) throw INVALID_OPERATION('Could not load node: ' + index)
        return Promise.resolve(null)
      }
      return Promise.resolve(node)
    }

    return getStoredNode(this.storage, index, this.cache, error)
  }

  async flush () {
    this.flushing = this.unflushed
    this.unflushed = new Map()

    try {
      if (this.truncated) await this._flushTruncation()
      await this._flushNodes()
    } catch (err) {
      for (const node of this.flushing.values()) {
        if (!this.unflushed.has(node.index)) this.unflushed.set(node.index, node)
      }
      throw err
    } finally {
      this.flushing = null
    }
  }

  _flushTruncation () {
    return new Promise((resolve, reject) => {
      const t = this.truncateTo
      const offset = t === 0 ? 0 : (t - 1) * 80 + 40

      this.storage.truncate(offset, (err) => {
        if (err) return reject(err)

        if (this.truncateTo === t) {
          this.truncateTo = 0
          this.truncated = false
        }

        resolve()
      })
    })
  }

  _flushNodes () {
    // TODO: write neighbors together etc etc
    // TODO: bench loading a full disk page and copy to that instead
    return new Promise((resolve, reject) => {
      const slab = b4a.allocUnsafe(40 * this.flushing.size)

      let error = null
      let missing = this.flushing.size + 1
      let offset = 0

      for (const node of this.flushing.values()) {
        const state = {
          start: 0,
          end: 40,
          buffer: slab.subarray(offset, offset += 40)
        }

        c.uint64.encode(state, node.size)
        c.raw.encode(state, node.hash)

        this.storage.write(node.index * 40, state.buffer, done)
      }

      done(null)

      function done (err) {
        if (err) error = err
        if (--missing > 0) return
        if (error) reject(error)
        else resolve()
      }
    })
  }

  clear () {
    this.cache = new Xache({ maxSize: this.cache.maxSize })
    this.truncated = true
    this.truncateTo = 0
    this.roots = []
    this.length = 0
    this.byteLength = 0
    this.fork = 0
    this.signature = null
    if (this.flushing !== null) this.flushing.clear()
    this.unflushed.clear()
    return this.flush()
  }

  close () {
    return new Promise((resolve, reject) => {
      this.storage.close(err => {
        if (err) reject(err)
        else resolve()
      })
    })
  }

  async truncate (length, fork = this.fork) {
    const head = length * 2
    const batch = new MerkleTreeBatch(this)
    const fullRoots = flat.fullRoots(head)

    for (let i = 0; i < fullRoots.length; i++) {
      const root = fullRoots[i]
      if (i < batch.roots.length && batch.roots[i].index === root) continue

      while (batch.roots.length > i) batch.roots.pop()
      batch.roots.push(await this.get(root))
    }

    while (batch.roots.length > fullRoots.length) {
      batch.roots.pop()
    }

    batch.fork = fork
    batch.length = length
    batch.ancestors = length
    batch.byteLength = totalSize(batch.roots)
    batch.upgraded = true

    return batch
  }

  async reorg (proof) {
    const batch = new ReorgBatch(this)

    let unverified = null

    if (proof.block || proof.hash || proof.seek) {
      unverified = verifyTree(proof, this.crypto, batch.nodes)
    }

    if (!verifyUpgrade(proof, unverified, batch)) {
      throw INVALID_PROOF('Fork proof not verifiable')
    }

    for (const root of batch.roots) {
      const existing = await this.get(root.index, false)
      if (existing && b4a.equals(existing.hash, root.hash)) continue
      batch._updateDiffRoot(root)
      break
    }

    if (batch.diff !== null) {
      await batch._update(batch.nodes)
    } else {
      batch.want = null
      batch.ancestors = batch.length
    }

    return batch
  }

  verifyFullyRemote (proof) {
    // TODO: impl this less hackishly
    const batch = new MerkleTreeBatch(this)

    batch.fork = proof.fork
    batch.roots = []
    batch.length = 0
    batch.ancestors = 0
    batch.byteLength = 0

    let unverified = verifyTree(proof, this.crypto, batch.nodes)

    if (proof.upgrade) {
      if (verifyUpgrade(proof, unverified, batch)) {
        unverified = null
      }
    }

    return batch
  }

  async verify (proof) {
    const batch = new MerkleTreeBatch(this)

    let unverified = verifyTree(proof, this.crypto, batch.nodes)

    if (proof.upgrade) {
      if (verifyUpgrade(proof, unverified, batch)) {
        unverified = null
      }
    }

    if (unverified) {
      const verified = await this.get(unverified.index)
      if (!b4a.equals(verified.hash, unverified.hash)) {
        throw INVALID_CHECKSUM('Invalid checksum at node ' + unverified.index)
      }
    }

    return batch
  }

  proof ({ block, hash, seek, upgrade }) {
    return generateProof(this, block, hash, seek, upgrade)
  }

  // Successor to .nodes()
  async missingNodes (index) {
    const head = 2 * this.length
    const ite = flat.iterator(index)

    // See iterator.rightSpan()
    const iteRightSpan = ite.index + ite.factor / 2 - 1
    // If the index is not in the current tree, we do not know how many missing nodes there are...
    if (iteRightSpan >= head) return 0

    let cnt = 0
    while (!ite.contains(head) && (await this.get(ite.index, false)) === null) {
      cnt++
      ite.parent()
    }

    return cnt
  }

  // Deprecated
  async nodes (index) {
    const head = 2 * this.length
    const ite = flat.iterator(index)

    let cnt = 0
    while (!ite.contains(head) && (await this.get(ite.index, false)) === null) {
      cnt++
      ite.parent()
    }

    return cnt
  }

  byteRange (index) {
    return getByteRange(this, index)
  }

  byteOffset (index) {
    return getByteOffset(this, index)
  }

  static async open (storage, opts = {}) {
    await new Promise((resolve, reject) => {
      storage.read(0, OLD_TREE.length, (err, buf) => {
        if (err) return resolve()
        if (b4a.equals(buf, OLD_TREE)) return reject(new Error('Storage contains an incompatible merkle tree'))
        resolve()
      })
    })

    const length = typeof opts.length === 'number'
      ? opts.length
      : await autoLength(storage)

    const roots = []
    for (const index of flat.fullRoots(2 * length)) {
      roots.push(await getStoredNode(storage, index, null, true))
    }

    return new MerkleTree(storage, roots, opts.fork || 0, opts.signature || null)
  }
}

async function getByteRange (tree, index) {
  const head = 2 * tree.length
  if (((index & 1) === 0 ? index : flat.rightSpan(index)) >= head) {
    throw BAD_ARGUMENT('Index is out of bounds')
  }
  return [await tree.byteOffset(index), (await tree.get(index)).size]
}

async function getByteOffset (tree, index) {
  if (index === 2 * tree.length) return tree.byteLength
  if ((index & 1) === 1) index = flat.leftSpan(index)

  let head = 0
  let offset = 0

  for (const node of tree.roots) { // all async ticks happen once we find the root so safe
    head += 2 * ((node.index - head) + 1)

    if (index >= head) {
      offset += node.size
      continue
    }

    const ite = flat.iterator(node.index)

    while (ite.index !== index) {
      if (index < ite.index) {
        ite.leftChild()
      } else {
        offset += (await tree.get(ite.leftChild())).size
        ite.sibling()
      }
    }

    return offset
  }
}

// All the methods needed for proof verification

function verifyTree ({ block, hash, seek }, crypto, nodes) {
  const untrustedNode = block
    ? { index: 2 * block.index, value: block.value, nodes: block.nodes }
    : hash
      ? { index: hash.index, value: null, nodes: hash.nodes }
      : null

  if (untrustedNode === null && (!seek || !seek.nodes.length)) return null

  let root = null

  if (seek && seek.nodes.length) {
    const ite = flat.iterator(seek.nodes[0].index)
    const q = new NodeQueue(seek.nodes)

    root = q.shift(ite.index)
    nodes.push(root)

    while (q.length > 0) {
      const node = q.shift(ite.sibling())

      root = parentNode(crypto, ite.parent(), root, node)
      nodes.push(node)
      nodes.push(root)
    }
  }

  if (untrustedNode === null) return root

  const ite = flat.iterator(untrustedNode.index)
  const blockHash = untrustedNode.value && blockNode(crypto, ite.index, untrustedNode.value)

  const q = new NodeQueue(untrustedNode.nodes, root)

  root = blockHash || q.shift(ite.index)
  nodes.push(root)

  while (q.length > 0) {
    const node = q.shift(ite.sibling())

    root = parentNode(crypto, ite.parent(), root, node)
    nodes.push(node)
    nodes.push(root)
  }

  return root
}

function verifyUpgrade ({ fork, upgrade }, blockRoot, batch) {
  const q = new NodeQueue(upgrade.nodes, blockRoot)

  let grow = batch.roots.length > 0
  let i = 0

  const to = 2 * (upgrade.start + upgrade.length)
  const ite = flat.iterator(0)

  for (; ite.fullRoot(to); ite.nextTree()) {
    if (i < batch.roots.length && batch.roots[i].index === ite.index) {
      i++
      continue
    }

    if (grow) {
      grow = false
      const root = ite.index
      if (i < batch.roots.length) {
        ite.seek(batch.roots[batch.roots.length - 1].index)
        while (ite.index !== root) {
          batch.appendRoot(q.shift(ite.sibling()), ite)
        }
        continue
      }
    }

    batch.appendRoot(q.shift(ite.index), ite)
  }

  const extra = upgrade.additionalNodes

  ite.seek(batch.roots[batch.roots.length - 1].index)
  i = 0

  while (i < extra.length && extra[i].index === ite.sibling()) {
    batch.appendRoot(extra[i++], ite)
  }

  while (i < extra.length) {
    const node = extra[i++]

    while (node.index !== ite.index) {
      if (ite.factor === 2) throw INVALID_OPERATION('Unexpected node: ' + node.index)
      ite.leftChild()
    }

    batch.appendRoot(node, ite)
    ite.sibling()
  }

  batch.signature = upgrade.signature
  batch.fork = fork

  return q.extra === null
}

async function seekFromHead (tree, head, bytes, padding) {
  const roots = flat.fullRoots(head)

  for (let i = 0; i < roots.length; i++) {
    const root = roots[i]
    const node = await tree.get(root)
    const size = getUnpaddedSize(node, padding, null)

    if (bytes === size) return root
    if (bytes > size) {
      bytes -= size
      continue
    }

    return seekTrustedTree(tree, root, bytes, padding)
  }

  return head
}

// trust that bytes are within the root tree and find the block at bytes

async function seekTrustedTree (tree, root, bytes, padding) {
  if (!bytes) return root

  const ite = flat.iterator(root)

  while ((ite.index & 1) !== 0) {
    const l = await tree.get(ite.leftChild(), false)
    if (l) {
      const size = getUnpaddedSize(l, padding, ite)
      if (size === bytes) return ite.index
      if (size > bytes) continue
      bytes -= size
      ite.sibling()
    } else {
      ite.parent()
      return ite.index
    }
  }

  return ite.index
}

// try to find the block at bytes without trusting that is *is* within the root passed

async function seekUntrustedTree (tree, root, bytes, padding) {
  const offset = await tree.byteOffset(root) - (padding ? padding * flat.leftSpan(root) / 2 : 0)

  if (offset > bytes) throw INVALID_OPERATION('Invalid seek')
  if (offset === bytes) return root

  bytes -= offset

  const node = await tree.get(root)

  if (getUnpaddedSize(node, padding, null) <= bytes) throw INVALID_OPERATION('Invalid seek')

  return seekTrustedTree(tree, root, bytes, padding)
}

// Below is proof production, ie, construct proofs to verify a request
// Note, that all these methods are sync as we can statically infer which nodes
// are needed for the remote to verify given they arguments they passed us

function seekProof (tree, seekRoot, root, p) {
  const ite = flat.iterator(seekRoot)

  p.seek = []
  p.seek.push(tree.get(ite.index))

  while (ite.index !== root) {
    ite.sibling()
    p.seek.push(tree.get(ite.index))
    ite.parent()
  }
}

function blockAndSeekProof (tree, node, seek, seekRoot, root, p) {
  if (!node) return seekProof(tree, seekRoot, root, p)

  const ite = flat.iterator(node.index)

  p.node = []
  if (!node.value) p.node.push(tree.get(ite.index))

  while (ite.index !== root) {
    ite.sibling()

    if (seek && ite.contains(seekRoot) && ite.index !== seekRoot) {
      seekProof(tree, seekRoot, ite.index, p)
    } else {
      p.node.push(tree.get(ite.index))
    }

    ite.parent()
  }
}

function upgradeProof (tree, node, seek, from, to, subTree, p) {
  if (from === 0) p.upgrade = []

  for (const ite = flat.iterator(0); ite.fullRoot(to); ite.nextTree()) {
    // check if they already have the node
    if (ite.index + ite.factor / 2 < from) continue

    // connect existing tree
    if (p.upgrade === null && ite.contains(from - 2)) {
      p.upgrade = []

      const root = ite.index
      const target = from - 2

      ite.seek(target)

      while (ite.index !== root) {
        ite.sibling()
        if (ite.index > target) {
          if (p.node === null && p.seek === null && ite.contains(subTree)) {
            blockAndSeekProof(tree, node, seek, subTree, ite.index, p)
          } else {
            p.upgrade.push(tree.get(ite.index))
          }
        }
        ite.parent()
      }

      continue
    }

    if (p.upgrade === null) {
      p.upgrade = []
    }

    // if the subtree included is a child of this tree, include that one
    // instead of a dup node
    if (p.node === null && p.seek === null && ite.contains(subTree)) {
      blockAndSeekProof(tree, node, seek, subTree, ite.index, p)
      continue
    }

    // add root (can be optimised since the root might be in tree.roots)
    p.upgrade.push(tree.get(ite.index))
  }
}

function additionalUpgradeProof (tree, from, to, p) {
  if (from === 0) p.additionalUpgrade = []

  for (const ite = flat.iterator(0); ite.fullRoot(to); ite.nextTree()) {
    // check if they already have the node
    if (ite.index + ite.factor / 2 < from) continue

    // connect existing tree
    if (p.additionalUpgrade === null && ite.contains(from - 2)) {
      p.additionalUpgrade = []

      const root = ite.index
      const target = from - 2

      ite.seek(target)

      while (ite.index !== root) {
        ite.sibling()
        if (ite.index > target) {
          p.additionalUpgrade.push(tree.get(ite.index))
        }
        ite.parent()
      }

      continue
    }

    if (p.additionalUpgrade === null) {
      p.additionalUpgrade = []
    }

    // add root (can be optimised since the root is in tree.roots)
    p.additionalUpgrade.push(tree.get(ite.index))
  }
}

function nodesToRoot (index, nodes, head) {
  const ite = flat.iterator(index)

  for (let i = 0; i < nodes; i++) {
    ite.parent()
    if (ite.contains(head)) throw BAD_ARGUMENT('Nodes is out of bounds')
  }

  return ite.index
}

function totalSize (nodes) {
  let s = 0
  for (const node of nodes) s += node.size
  return s
}

function totalSpan (nodes) {
  let s = 0
  for (const node of nodes) s += 2 * ((node.index - s) + 1)
  return s
}

function blockNode (crypto, index, value) {
  return { index, size: value.byteLength, hash: crypto.data(value) }
}

function parentNode (crypto, index, a, b) {
  return { index, size: a.size + b.size, hash: crypto.parent(a, b) }
}

function blankNode (index) {
  return { index, size: 0, hash: BLANK_HASH }
}

// Storage methods

function getStoredNode (storage, index, cache, error) {
  return new Promise((resolve, reject) => {
    storage.read(40 * index, 40, (err, data) => {
      if (err) {
        if (error) return reject(err)
        else resolve(null)
        return
      }

      const hash = data.subarray(8)
      const size = c.decode(c.uint64, data)

      if (size === 0 && b4a.compare(hash, BLANK_HASH) === 0) {
        if (error) reject(new Error('Could not load node: ' + index))
        else resolve(null)
        return
      }

      const node = { index, size, hash }
      if (cache !== null) cache.set(index, node)
      resolve(node)
    })
  })
}

function storedNodes (storage) {
  return new Promise((resolve) => {
    storage.stat((_, st) => {
      if (!st) return resolve(0)
      resolve((st.size - (st.size % 40)) / 40)
    })
  })
}

async function autoLength (storage) {
  const nodes = await storedNodes(storage)
  if (!nodes) return 0
  const ite = flat.iterator(nodes - 1)
  let index = nodes - 1
  while (await getStoredNode(storage, ite.parent(), null, false)) index = ite.index
  return flat.rightSpan(index) / 2 + 1
}

function truncateMap (map, len) {
  for (const node of map.values()) {
    if (node.index >= 2 * len) map.delete(node.index)
  }
}

function log2 (n) {
  let res = 1

  while (n > 2) {
    n /= 2
    res++
  }

  return res
}

function normalizeIndexed (block, hash) {
  if (block) return { value: true, index: block.index * 2, nodes: block.nodes, lastIndex: block.index }
  if (hash) return { value: false, index: hash.index, nodes: hash.nodes, lastIndex: flat.rightSpan(hash.index) / 2 }
  return null
}

async function settleProof (p) {
  const result = [
    p.node && Promise.all(p.node),
    p.seek && Promise.all(p.seek),
    p.upgrade && Promise.all(p.upgrade),
    p.additionalUpgrade && Promise.all(p.additionalUpgrade)
  ]

  try {
    return await Promise.all(result)
  } catch (err) {
    if (p.node) await Promise.allSettled(p.node)
    if (p.seek) await Promise.allSettled(p.seek)
    if (p.upgrade) await Promise.allSettled(p.upgrade)
    if (p.additionalUpgrade) await Promise.allSettled(p.additionalUpgrade)
    throw err
  }
}

// tree can be either the merkle tree or a merkle tree batch
async function generateProof (tree, block, hash, seek, upgrade) {
  // Important that this does not throw inbetween making the promise arrays
  // and finalise being called, otherwise there will be lingering promises in the background

  const fork = tree.fork
  const signature = tree.signature
  const head = 2 * tree.length
  const from = upgrade ? upgrade.start * 2 : 0
  const to = upgrade ? from + upgrade.length * 2 : head
  const node = normalizeIndexed(block, hash)

  const result = { fork, block: null, hash: null, seek: null, upgrade: null, manifest: null }

  // can't do anything as we have no data...
  if (head === 0) return result

  if (from >= to || to > head) {
    throw INVALID_OPERATION('Invalid upgrade')
  }
  if (seek && upgrade && node !== null && node.index >= from) {
    throw INVALID_OPERATION('Cannot both do a seek and block/hash request when upgrading')
  }

  let subTree = head

  const p = {
    node: null,
    seek: null,
    upgrade: null,
    additionalUpgrade: null
  }

  if (node !== null && (!upgrade || node.lastIndex < upgrade.start)) {
    subTree = nodesToRoot(node.index, node.nodes, to)
    const seekRoot = seek ? await seekUntrustedTree(tree, subTree, seek.bytes, seek.padding) : head
    blockAndSeekProof(tree, node, seek, seekRoot, subTree, p)
  } else if ((node || seek) && upgrade) {
    subTree = seek ? await seekFromHead(tree, to, seek.bytes, seek.padding) : node.index
  }

  if (upgrade) {
    upgradeProof(tree, node, seek, from, to, subTree, p)
    if (head > to) additionalUpgradeProof(tree, to, head, p)
  }

  const [pNode, pSeek, pUpgrade, pAdditional] = await settleProof(p)

  if (block) {
    result.block = {
      index: block.index,
      value: null, // populated upstream, alloc it here for simplicity
      nodes: pNode
    }
  } else if (hash) {
    result.hash = {
      index: hash.index,
      nodes: pNode
    }
  }

  if (seek && pSeek !== null) {
    result.seek = {
      bytes: seek.bytes,
      nodes: pSeek
    }
  }

  if (upgrade) {
    result.upgrade = {
      start: upgrade.start,
      length: upgrade.length,
      nodes: pUpgrade,
      additionalNodes: pAdditional || [],
      signature
    }
  }

  return result
}

function getUnpaddedSize (node, padding, ite) {
  return padding === 0 ? node.size : node.size - padding * (ite ? ite.countLeaves() : flat.countLeaves(node.index))
}

},{"./caps":35,"b4a":4,"compact-encoding":16,"flat-tree":25,"hypercore-crypto":26,"hypercore-errors":27,"xache":130}],42:[function(require,module,exports){
const c = require('compact-encoding')
const b4a = require('b4a')
const { DEFAULT_NAMESPACE } = require('./caps')
const { INVALID_OPLOG_VERSION } = require('hypercore-errors')

const EMPTY = b4a.alloc(0)

const hashes = {
  preencode (state, m) {
    state.end++ // small uint
  },
  encode (state, m) {
    if (m === 'blake2b') {
      c.uint.encode(state, 0)
      return
    }

    throw new Error('Unknown hash: ' + m)
  },
  decode (state) {
    const n = c.uint.decode(state)
    if (n === 0) return 'blake2b'
    throw new Error('Unknown hash id: ' + n)
  }
}

const signatures = {
  preencode (state, m) {
    state.end++ // small uint
  },
  encode (state, m) {
    if (m === 'ed25519') {
      c.uint.encode(state, 0)
      return
    }

    throw new Error('Unknown signature: ' + m)
  },
  decode (state) {
    const n = c.uint.decode(state)
    if (n === 0) return 'ed25519'
    throw new Error('Unknown signature id: ' + n)
  }
}

const signer = {
  preencode (state, m) {
    signatures.preencode(state, m.signature)
    c.fixed32.preencode(state, m.namespace)
    c.fixed32.preencode(state, m.publicKey)
  },
  encode (state, m) {
    signatures.encode(state, m.signature)
    c.fixed32.encode(state, m.namespace)
    c.fixed32.encode(state, m.publicKey)
  },
  decode (state) {
    return {
      signature: signatures.decode(state),
      namespace: c.fixed32.decode(state),
      publicKey: c.fixed32.decode(state)
    }
  }
}

const signerArray = c.array(signer)

const multipleSigners = {
  preencode (state, m) {
    state.end++ // flags
    c.uint.preencode(state, m.quorum)
    signerArray.preencode(state, m.signers)
  },
  encode (state, m) {
    c.uint.encode(state, m.allowPatched ? 1 : 0)
    c.uint.encode(state, m.quorum)
    signerArray.encode(state, m.signers)
  },
  decode (state) {
    const flags = c.uint.decode(state)
    return {
      allowPatched: (flags & 1) !== 0,
      quorum: c.uint.decode(state),
      signers: signerArray.decode(state)
    }
  }
}

const manifest = exports.manifest = {
  preencode (state, m) {
    c.uint.preencode(state, 0) // version
    hashes.preencode(state, m.hash)
    c.uint.preencode(state, 2) // type

    if (m.static) {
      c.fixed32.preencode(state, m.static)
    }

    if (m.signer) {
      signer.preencode(state, m.signer)
    }

    if (m.multipleSigners) {
      multipleSigners.preencode(state, m.multipleSigners)
    }
  },
  encode (state, m) {
    c.uint.encode(state, 0) // version
    hashes.encode(state, m.hash)
    c.uint.encode(state, m.signer ? 1 : m.multipleSigners ? 2 : 0)

    if (m.static) {
      c.fixed32.encode(state, m.static)
    }

    if (m.signer) {
      signer.encode(state, m.signer)
    }

    if (m.multipleSigners) {
      multipleSigners.encode(state, m.multipleSigners)
    }
  },
  decode (state) {
    const version = c.uint.decode(state)
    if (version !== 0) throw new Error('Invalid version: ' + version)

    const hash = hashes.decode(state)
    const type = c.uint.decode(state)

    if (type > 2) throw new Error('Unknown type: ' + type)

    return {
      hash,
      static: type === 0 ? c.fixed32.decode(state) : null,
      signer: type === 1 ? signer.decode(state) : null,
      multipleSigners: type === 2 ? multipleSigners.decode(state) : null
    }
  }
}

const node = {
  preencode (state, n) {
    c.uint.preencode(state, n.index)
    c.uint.preencode(state, n.size)
    c.fixed32.preencode(state, n.hash)
  },
  encode (state, n) {
    c.uint.encode(state, n.index)
    c.uint.encode(state, n.size)
    c.fixed32.encode(state, n.hash)
  },
  decode (state) {
    return {
      index: c.uint.decode(state),
      size: c.uint.decode(state),
      hash: c.fixed32.decode(state)
    }
  }
}

const nodeArray = c.array(node)

const wire = exports.wire = {}

wire.handshake = {
  preencode (state, m) {
    c.uint.preencode(state, 1)
    c.fixed32.preencode(state, m.capability)
  },
  encode (state, m) {
    c.uint.encode(state, m.seeks ? 1 : 0)
    c.fixed32.encode(state, m.capability)
  },
  decode (state) {
    const flags = c.uint.decode(state)
    return {
      seeks: (flags & 1) !== 0,
      capability: c.fixed32.decode(state)
    }
  }
}

const requestBlock = {
  preencode (state, b) {
    c.uint.preencode(state, b.index)
    c.uint.preencode(state, b.nodes)
  },
  encode (state, b) {
    c.uint.encode(state, b.index)
    c.uint.encode(state, b.nodes)
  },
  decode (state) {
    return {
      index: c.uint.decode(state),
      nodes: c.uint.decode(state)
    }
  }
}

const requestSeek = {
  preencode (state, s) {
    c.uint.preencode(state, s.bytes)
    c.uint.preencode(state, s.padding)
  },
  encode (state, s) {
    c.uint.encode(state, s.bytes)
    c.uint.encode(state, s.padding)
  },
  decode (state) {
    return {
      bytes: c.uint.decode(state),
      padding: c.uint.decode(state)
    }
  }
}

const requestUpgrade = {
  preencode (state, u) {
    c.uint.preencode(state, u.start)
    c.uint.preencode(state, u.length)
  },
  encode (state, u) {
    c.uint.encode(state, u.start)
    c.uint.encode(state, u.length)
  },
  decode (state) {
    return {
      start: c.uint.decode(state),
      length: c.uint.decode(state)
    }
  }
}

wire.request = {
  preencode (state, m) {
    state.end++ // flags
    c.uint.preencode(state, m.id)
    c.uint.preencode(state, m.fork)

    if (m.block) requestBlock.preencode(state, m.block)
    if (m.hash) requestBlock.preencode(state, m.hash)
    if (m.seek) requestSeek.preencode(state, m.seek)
    if (m.upgrade) requestUpgrade.preencode(state, m.upgrade)
    if (m.priority) c.uint.preencode(state, m.priority)
  },
  encode (state, m) {
    const flags = (m.block ? 1 : 0) | (m.hash ? 2 : 0) | (m.seek ? 4 : 0) | (m.upgrade ? 8 : 0) | (m.manifest ? 16 : 0) | (m.priority ? 32 : 0)

    c.uint.encode(state, flags)
    c.uint.encode(state, m.id)
    c.uint.encode(state, m.fork)

    if (m.block) requestBlock.encode(state, m.block)
    if (m.hash) requestBlock.encode(state, m.hash)
    if (m.seek) requestSeek.encode(state, m.seek)
    if (m.upgrade) requestUpgrade.encode(state, m.upgrade)
    if (m.priority) c.uint.encode(state, m.priority)
  },
  decode (state) {
    const flags = c.uint.decode(state)

    return {
      id: c.uint.decode(state),
      fork: c.uint.decode(state),
      block: flags & 1 ? requestBlock.decode(state) : null,
      hash: flags & 2 ? requestBlock.decode(state) : null,
      seek: flags & 4 ? requestSeek.decode(state) : null,
      upgrade: flags & 8 ? requestUpgrade.decode(state) : null,
      manifest: (flags & 16) !== 0,
      priority: flags & 32 ? c.uint.decode(state) : 0
    }
  }
}

wire.cancel = {
  preencode (state, m) {
    c.uint.preencode(state, m.request)
  },
  encode (state, m) {
    c.uint.encode(state, m.request)
  },
  decode (state, m) {
    return {
      request: c.uint.decode(state)
    }
  }
}

const dataUpgrade = {
  preencode (state, u) {
    c.uint.preencode(state, u.start)
    c.uint.preencode(state, u.length)
    nodeArray.preencode(state, u.nodes)
    nodeArray.preencode(state, u.additionalNodes)
    c.buffer.preencode(state, u.signature)
  },
  encode (state, u) {
    c.uint.encode(state, u.start)
    c.uint.encode(state, u.length)
    nodeArray.encode(state, u.nodes)
    nodeArray.encode(state, u.additionalNodes)
    c.buffer.encode(state, u.signature)
  },
  decode (state) {
    return {
      start: c.uint.decode(state),
      length: c.uint.decode(state),
      nodes: nodeArray.decode(state),
      additionalNodes: nodeArray.decode(state),
      signature: c.buffer.decode(state)
    }
  }
}

const dataSeek = {
  preencode (state, s) {
    c.uint.preencode(state, s.bytes)
    nodeArray.preencode(state, s.nodes)
  },
  encode (state, s) {
    c.uint.encode(state, s.bytes)
    nodeArray.encode(state, s.nodes)
  },
  decode (state) {
    return {
      bytes: c.uint.decode(state),
      nodes: nodeArray.decode(state)
    }
  }
}

const dataBlock = {
  preencode (state, b) {
    c.uint.preencode(state, b.index)
    c.buffer.preencode(state, b.value)
    nodeArray.preencode(state, b.nodes)
  },
  encode (state, b) {
    c.uint.encode(state, b.index)
    c.buffer.encode(state, b.value)
    nodeArray.encode(state, b.nodes)
  },
  decode (state) {
    return {
      index: c.uint.decode(state),
      value: c.buffer.decode(state) || EMPTY,
      nodes: nodeArray.decode(state)
    }
  }
}

const dataHash = {
  preencode (state, b) {
    c.uint.preencode(state, b.index)
    nodeArray.preencode(state, b.nodes)
  },
  encode (state, b) {
    c.uint.encode(state, b.index)
    nodeArray.encode(state, b.nodes)
  },
  decode (state) {
    return {
      index: c.uint.decode(state),
      nodes: nodeArray.decode(state)
    }
  }
}

wire.data = {
  preencode (state, m) {
    state.end++ // flags
    c.uint.preencode(state, m.request)
    c.uint.preencode(state, m.fork)

    if (m.block) dataBlock.preencode(state, m.block)
    if (m.hash) dataHash.preencode(state, m.hash)
    if (m.seek) dataSeek.preencode(state, m.seek)
    if (m.upgrade) dataUpgrade.preencode(state, m.upgrade)
    if (m.manifest) manifest.preencode(state, m.manifest)
  },
  encode (state, m) {
    const flags = (m.block ? 1 : 0) | (m.hash ? 2 : 0) | (m.seek ? 4 : 0) | (m.upgrade ? 8 : 0) | (m.manifest ? 16 : 0)

    c.uint.encode(state, flags)
    c.uint.encode(state, m.request)
    c.uint.encode(state, m.fork)

    if (m.block) dataBlock.encode(state, m.block)
    if (m.hash) dataHash.encode(state, m.hash)
    if (m.seek) dataSeek.encode(state, m.seek)
    if (m.upgrade) dataUpgrade.encode(state, m.upgrade)
    if (m.manifest) manifest.encode(state, m.manifest)
  },
  decode (state) {
    const flags = c.uint.decode(state)

    return {
      request: c.uint.decode(state),
      fork: c.uint.decode(state),
      block: flags & 1 ? dataBlock.decode(state) : null,
      hash: flags & 2 ? dataHash.decode(state) : null,
      seek: flags & 4 ? dataSeek.decode(state) : null,
      upgrade: flags & 8 ? dataUpgrade.decode(state) : null,
      manifest: flags & 16 ? manifest.decode(state) : null
    }
  }
}

wire.noData = {
  preencode (state, m) {
    c.uint.preencode(state, m.request)
  },
  encode (state, m) {
    c.uint.encode(state, m.request)
  },
  decode (state, m) {
    return {
      request: c.uint.decode(state)
    }
  }
}

wire.want = {
  preencode (state, m) {
    c.uint.preencode(state, m.start)
    c.uint.preencode(state, m.length)
  },
  encode (state, m) {
    c.uint.encode(state, m.start)
    c.uint.encode(state, m.length)
  },
  decode (state) {
    return {
      start: c.uint.decode(state),
      length: c.uint.decode(state)
    }
  }
}

wire.unwant = {
  preencode (state, m) {
    c.uint.preencode(state, m.start)
    c.uint.preencode(state, m.length)
  },
  encode (state, m) {
    c.uint.encode(state, m.start)
    c.uint.encode(state, m.length)
  },
  decode (state, m) {
    return {
      start: c.uint.decode(state),
      length: c.uint.decode(state)
    }
  }
}

wire.range = {
  preencode (state, m) {
    state.end++ // flags
    c.uint.preencode(state, m.start)
    if (m.length !== 1) c.uint.preencode(state, m.length)
  },
  encode (state, m) {
    c.uint.encode(state, (m.drop ? 1 : 0) | (m.length === 1 ? 2 : 0))
    c.uint.encode(state, m.start)
    if (m.length !== 1) c.uint.encode(state, m.length)
  },
  decode (state) {
    const flags = c.uint.decode(state)

    return {
      drop: (flags & 1) !== 0,
      start: c.uint.decode(state),
      length: (flags & 2) !== 0 ? 1 : c.uint.decode(state)
    }
  }
}

wire.bitfield = {
  preencode (state, m) {
    c.uint.preencode(state, m.start)
    c.uint32array.preencode(state, m.bitfield)
  },
  encode (state, m) {
    c.uint.encode(state, m.start)
    c.uint32array.encode(state, m.bitfield)
  },
  decode (state, m) {
    return {
      start: c.uint.decode(state),
      bitfield: c.uint32array.decode(state)
    }
  }
}

wire.sync = {
  preencode (state, m) {
    state.end++ // flags
    c.uint.preencode(state, m.fork)
    c.uint.preencode(state, m.length)
    c.uint.preencode(state, m.remoteLength)
  },
  encode (state, m) {
    c.uint.encode(state, (m.canUpgrade ? 1 : 0) | (m.uploading ? 2 : 0) | (m.downloading ? 4 : 0) | (m.hasManifest ? 8 : 0))
    c.uint.encode(state, m.fork)
    c.uint.encode(state, m.length)
    c.uint.encode(state, m.remoteLength)
  },
  decode (state) {
    const flags = c.uint.decode(state)

    return {
      fork: c.uint.decode(state),
      length: c.uint.decode(state),
      remoteLength: c.uint.decode(state),
      canUpgrade: (flags & 1) !== 0,
      uploading: (flags & 2) !== 0,
      downloading: (flags & 4) !== 0,
      hasManifest: (flags & 8) !== 0
    }
  }
}

wire.reorgHint = {
  preencode (state, m) {
    c.uint.preencode(state, m.from)
    c.uint.preencode(state, m.to)
    c.uint.preencode(state, m.ancestors)
  },
  encode (state, m) {
    c.uint.encode(state, m.from)
    c.uint.encode(state, m.to)
    c.uint.encode(state, m.ancestors)
  },
  decode (state) {
    return {
      from: c.uint.encode(state),
      to: c.uint.encode(state),
      ancestors: c.uint.encode(state)
    }
  }
}

wire.extension = {
  preencode (state, m) {
    c.string.preencode(state, m.name)
    c.raw.preencode(state, m.message)
  },
  encode (state, m) {
    c.string.encode(state, m.name)
    c.raw.encode(state, m.message)
  },
  decode (state) {
    return {
      name: c.string.decode(state),
      message: c.raw.decode(state)
    }
  }
}

const keyValue = {
  preencode (state, p) {
    c.string.preencode(state, p.key)
    c.buffer.preencode(state, p.value)
  },
  encode (state, p) {
    c.string.encode(state, p.key)
    c.buffer.encode(state, p.value)
  },
  decode (state) {
    return {
      key: c.string.decode(state),
      value: c.buffer.decode(state)
    }
  }
}

const treeUpgrade = {
  preencode (state, u) {
    c.uint.preencode(state, u.fork)
    c.uint.preencode(state, u.ancestors)
    c.uint.preencode(state, u.length)
    c.buffer.preencode(state, u.signature)
  },
  encode (state, u) {
    c.uint.encode(state, u.fork)
    c.uint.encode(state, u.ancestors)
    c.uint.encode(state, u.length)
    c.buffer.encode(state, u.signature)
  },
  decode (state) {
    return {
      fork: c.uint.decode(state),
      ancestors: c.uint.decode(state),
      length: c.uint.decode(state),
      signature: c.buffer.decode(state)
    }
  }
}

const bitfieldUpdate = { // TODO: can maybe be folded into a HAVE later on with the most recent spec
  preencode (state, b) {
    state.end++ // flags
    c.uint.preencode(state, b.start)
    c.uint.preencode(state, b.length)
  },
  encode (state, b) {
    state.buffer[state.start++] = b.drop ? 1 : 0
    c.uint.encode(state, b.start)
    c.uint.encode(state, b.length)
  },
  decode (state) {
    const flags = c.uint.decode(state)
    return {
      drop: (flags & 1) !== 0,
      start: c.uint.decode(state),
      length: c.uint.decode(state)
    }
  }
}

const oplog = exports.oplog = {}

oplog.entry = {
  preencode (state, m) {
    state.end++ // flags
    if (m.userData) keyValue.preencode(state, m.userData)
    if (m.treeNodes) nodeArray.preencode(state, m.treeNodes)
    if (m.treeUpgrade) treeUpgrade.preencode(state, m.treeUpgrade)
    if (m.bitfield) bitfieldUpdate.preencode(state, m.bitfield)
  },
  encode (state, m) {
    const s = state.start++
    let flags = 0

    if (m.userData) {
      flags |= 1
      keyValue.encode(state, m.userData)
    }
    if (m.treeNodes) {
      flags |= 2
      nodeArray.encode(state, m.treeNodes)
    }
    if (m.treeUpgrade) {
      flags |= 4
      treeUpgrade.encode(state, m.treeUpgrade)
    }
    if (m.bitfield) {
      flags |= 8
      bitfieldUpdate.encode(state, m.bitfield)
    }

    state.buffer[s] = flags
  },
  decode (state) {
    const flags = c.uint.decode(state)
    return {
      userData: (flags & 1) !== 0 ? keyValue.decode(state) : null,
      treeNodes: (flags & 2) !== 0 ? nodeArray.decode(state) : null,
      treeUpgrade: (flags & 4) !== 0 ? treeUpgrade.decode(state) : null,
      bitfield: (flags & 8) !== 0 ? bitfieldUpdate.decode(state) : null
    }
  }
}

const keyPair = {
  preencode (state, kp) {
    c.buffer.preencode(state, kp.publicKey)
    c.buffer.preencode(state, kp.secretKey)
  },
  encode (state, kp) {
    c.buffer.encode(state, kp.publicKey)
    c.buffer.encode(state, kp.secretKey)
  },
  decode (state) {
    return {
      publicKey: c.buffer.decode(state),
      secretKey: c.buffer.decode(state)
    }
  }
}

const reorgHint = {
  preencode (state, r) {
    c.uint.preencode(state, r.from)
    c.uint.preencode(state, r.to)
    c.uint.preencode(state, r.ancestors)
  },
  encode (state, r) {
    c.uint.encode(state, r.from)
    c.uint.encode(state, r.to)
    c.uint.encode(state, r.ancestors)
  },
  decode (state) {
    return {
      from: c.uint.decode(state),
      to: c.uint.decode(state),
      ancestors: c.uint.decode(state)
    }
  }
}

const reorgHintArray = c.array(reorgHint)

const hints = {
  preencode (state, h) {
    reorgHintArray.preencode(state, h.reorgs)
    c.uint.preencode(state, h.contiguousLength)
  },
  encode (state, h) {
    reorgHintArray.encode(state, h.reorgs)
    c.uint.encode(state, h.contiguousLength)
  },
  decode (state) {
    return {
      reorgs: reorgHintArray.decode(state),
      contiguousLength: state.start < state.end ? c.uint.decode(state) : 0
    }
  }
}

const treeHeader = {
  preencode (state, t) {
    c.uint.preencode(state, t.fork)
    c.uint.preencode(state, t.length)
    c.buffer.preencode(state, t.rootHash)
    c.buffer.preencode(state, t.signature)
  },
  encode (state, t) {
    c.uint.encode(state, t.fork)
    c.uint.encode(state, t.length)
    c.buffer.encode(state, t.rootHash)
    c.buffer.encode(state, t.signature)
  },
  decode (state) {
    return {
      fork: c.uint.decode(state),
      length: c.uint.decode(state),
      rootHash: c.buffer.decode(state),
      signature: c.buffer.decode(state)
    }
  }
}

const types = {
  preencode (state, t) {
    c.string.preencode(state, t.tree)
    c.string.preencode(state, t.bitfield)
    c.string.preencode(state, t.signer)
  },
  encode (state, t) {
    c.string.encode(state, t.tree)
    c.string.encode(state, t.bitfield)
    c.string.encode(state, t.signer)
  },
  decode (state) {
    return {
      tree: c.string.decode(state),
      bitfield: c.string.decode(state),
      signer: c.string.decode(state)
    }
  }
}

const externalHeader = {
  preencode (state, m) {
    c.uint.preencode(state, m.start)
    c.uint.preencode(state, m.length)
  },
  encode (state, m) {
    c.uint.encode(state, m.start)
    c.uint.encode(state, m.length)
  },
  decode (state) {
    return {
      start: c.uint.decode(state),
      length: c.uint.decode(state)
    }
  }
}

const keyValueArray = c.array(keyValue)

oplog.header = {
  preencode (state, h) {
    state.end += 2 // version + flags
    if (h.external) {
      externalHeader.preencode(state, h.external)
      return
    }
    c.fixed32.preencode(state, h.key)
    if (h.manifest) manifest.preencode(state, h.manifest)
    if (h.keyPair) keyPair.preencode(state, h.keyPair)
    keyValueArray.preencode(state, h.userData)
    treeHeader.preencode(state, h.tree)
    hints.preencode(state, h.hints)
  },
  encode (state, h) {
    c.uint.encode(state, 1)
    if (h.external) {
      c.uint.encode(state, 1) // ONLY set the first big for clarity
      externalHeader.encode(state, h.external)
      return
    }
    c.uint.encode(state, (h.manifest ? 2 : 0) | (h.keyPair ? 4 : 0))
    c.fixed32.encode(state, h.key)
    if (h.manifest) manifest.encode(state, h.manifest)
    if (h.keyPair) keyPair.encode(state, h.keyPair)
    keyValueArray.encode(state, h.userData)
    treeHeader.encode(state, h.tree)
    hints.encode(state, h.hints)
  },
  decode (state) {
    const version = c.uint.decode(state)

    if (version > 1) {
      throw INVALID_OPLOG_VERSION('Invalid header version. Expected <= 1, got ' + version)
    }

    if (version === 0) {
      const old = {
        types: types.decode(state),
        userData: keyValueArray.decode(state),
        tree: treeHeader.decode(state),
        signer: keyPair.decode(state),
        hints: hints.decode(state)
      }

      return {
        external: null,
        key: old.signer.publicKey,
        manifest: {
          hash: old.types.tree,
          static: null,
          signer: {
            signature: old.types.signer,
            namespace: DEFAULT_NAMESPACE,
            publicKey: old.signer.publicKey
          },
          multipleSigners: null
        },
        keyPair: old.signer.secretKey ? old.signer : null,
        userData: old.userData,
        tree: old.tree,
        hints: old.hints
      }
    }

    const flags = c.uint.decode(state)

    if (flags & 1) {
      return {
        external: externalHeader.decode(state),
        key: null,
        manifest: null,
        keyPair: null,
        userData: null,
        tree: null,
        hints: null
      }
    }

    return {
      external: null,
      key: c.fixed32.decode(state),
      manifest: (flags & 2) !== 0 ? manifest.decode(state) : null,
      keyPair: (flags & 4) !== 0 ? keyPair.decode(state) : null,
      userData: keyValueArray.decode(state),
      tree: treeHeader.decode(state),
      hints: hints.decode(state)
    }
  }
}

const uintArray = c.array(c.uint)

const patchEncoding = {
  preencode (state, n) {
    c.uint.preencode(state, n.start)
    c.uint.preencode(state, n.length)
    uintArray.preencode(state, n.nodes)
  },
  encode (state, n) {
    c.uint.encode(state, n.start)
    c.uint.encode(state, n.length)
    uintArray.encode(state, n.nodes)
  },
  decode (state) {
    return {
      start: c.uint.decode(state),
      length: c.uint.decode(state),
      nodes: uintArray.decode(state)
    }
  }
}

const multisigInput = {
  preencode (state, n) {
    state.end++
    c.uint.preencode(state, n.signer)
    c.fixed64.preencode(state, n.signature)
    if (n.patch) patchEncoding.preencode(state, n.patch)
  },
  encode (state, n) {
    c.uint.encode(state, n.patch ? 1 : 0)
    c.uint.encode(state, n.signer)
    c.fixed64.encode(state, n.signature)
    if (n.patch) patchEncoding.encode(state, n.patch)
  },
  decode (state) {
    const flags = c.uint.decode(state)
    return {
      signer: c.uint.decode(state),
      signature: c.fixed64.decode(state),
      patch: (flags & 1) ? patchEncoding.decode(state) : null
    }
  }
}

const multisigInputArray = c.array(multisigInput)

const compactNode = {
  preencode (state, n) {
    c.uint.preencode(state, n.index)
    c.uint.preencode(state, n.size)
    c.fixed32.preencode(state, n.hash)
  },
  encode (state, n) {
    c.uint.encode(state, n.index)
    c.uint.encode(state, n.size)
    c.fixed32.encode(state, n.hash)
  },
  decode (state) {
    return {
      index: c.uint.decode(state),
      size: c.uint.decode(state),
      hash: c.fixed32.decode(state)
    }
  }
}

const compactNodeArray = c.array(compactNode)

exports.multiSignature = {
  preencode (state, s) {
    multisigInputArray.preencode(state, s.proofs)
    compactNodeArray.preencode(state, s.nodes)
  },
  encode (state, s) {
    multisigInputArray.encode(state, s.proofs)
    compactNodeArray.encode(state, s.nodes)
  },
  decode (state) {
    return {
      proofs: multisigInputArray.decode(state),
      nodes: compactNodeArray.decode(state)
    }
  }
}

},{"./caps":35,"b4a":4,"compact-encoding":16,"hypercore-errors":27}],43:[function(require,module,exports){
const c = require('compact-encoding')
const b4a = require('b4a')
const encoding = require('./messages').multiSignature

module.exports = {
  assemble,
  inflate,
  partialSignature,
  signableLength
}

function inflate (data) {
  const compressedInputs = c.decode(encoding, data)
  const inputs = []

  for (const proof of compressedInputs.proofs) {
    inputs.push({
      signer: proof.signer,
      signature: proof.signature,
      patch: inflateUpgrade(proof.patch, compressedInputs.nodes)
    })
  }

  return inputs
}

async function partialSignature (tree, signer, from, to = tree.length, signature = tree.signature) {
  if (from > tree.length) return null
  const patch = to <= from ? null : await upgrade(tree, from, to)

  return {
    signer,
    signature,
    patch
  }
}

async function upgrade (tree, from, to) {
  const p = await tree.proof({ upgrade: { start: from, length: to - from } })
  p.upgrade.additionalNodes = []
  p.upgrade.signature = null
  return p.upgrade
}

function signableLength (lengths, quorum) {
  if (quorum <= 0) quorum = 1
  if (quorum > lengths.length) return 0

  return lengths.sort(cmp)[quorum - 1]
}

function cmp (a, b) {
  return b - a
}

function assemble (inputs) {
  const proofs = []
  const nodes = []

  for (const u of inputs) {
    proofs.push(compressProof(u, nodes))
  }

  return c.encode(encoding, { proofs, nodes })
}

function compareNode (a, b) {
  if (a.index !== b.index) return false
  if (a.size !== b.size) return false
  return b4a.equals(a.hash, b.hash)
}

function compressProof (proof, nodes) {
  return {
    signer: proof.signer,
    signature: proof.signature,
    patch: compressUpgrade(proof.patch, nodes)
  }
}

function compressUpgrade (p, nodes) {
  if (!p) return null

  const u = {
    start: p.start,
    length: p.length,
    nodes: []
  }

  for (const node of p.nodes) {
    let present = false
    for (let i = 0; i < nodes.length; i++) {
      if (!compareNode(nodes[i], node)) continue

      u.nodes.push(i)
      present = true
      break
    }

    if (present) continue
    u.nodes.push(nodes.push(node) - 1)
  }

  return u
}

function inflateUpgrade (s, nodes) {
  if (!s) return null

  const upgrade = {
    start: s.start,
    length: s.length,
    nodes: [],
    additionalNodes: [],
    signature: null
  }

  for (const i of s.nodes) {
    upgrade.nodes.push(nodes[i])
  }

  return upgrade
}

},{"./messages":42,"b4a":4,"compact-encoding":16}],44:[function(require,module,exports){
module.exports = class Mutex {
  constructor () {
    this.locked = false
    this.destroyed = false

    this._destroying = null
    this._destroyError = null
    this._queue = []
    this._enqueue = (resolve, reject) => this._queue.push([resolve, reject])
  }

  lock () {
    if (this.destroyed) return Promise.reject(this._destroyError || new Error('Mutex has been destroyed'))
    if (this.locked) return new Promise(this._enqueue)
    this.locked = true
    return Promise.resolve()
  }

  unlock () {
    if (!this._queue.length) {
      this.locked = false
      return
    }
    this._queue.shift()[0]()
  }

  destroy (err) {
    if (!this._destroying) this._destroying = this.locked ? this.lock().catch(() => {}) : Promise.resolve()

    this.destroyed = true
    if (err) this._destroyError = err

    if (err) {
      while (this._queue.length) this._queue.shift()[1](err)
    }

    return this._destroying
  }
}

},{}],45:[function(require,module,exports){
const cenc = require('compact-encoding')
const b4a = require('b4a')
const { crc32 } = require('crc-universal')
const { OPLOG_CORRUPT, OPLOG_HEADER_OVERFLOW } = require('hypercore-errors')

module.exports = class Oplog {
  constructor (storage, { pageSize = 4096, headerEncoding = cenc.raw, entryEncoding = cenc.raw, readonly = false } = {}) {
    this.storage = storage
    this.headerEncoding = headerEncoding
    this.entryEncoding = entryEncoding
    this.readonly = readonly
    this.flushed = false
    this.byteLength = 0
    this.length = 0

    this._headers = [1, 0]
    this._pageSize = pageSize
    this._entryOffset = pageSize * 2
  }

  _addHeader (state, len, headerBit, partialBit) {
    // add the uint header (frame length and flush info)
    state.start = state.start - len - 4
    cenc.uint32.encode(state, (len << 2) | headerBit | partialBit)

    // crc32 the length + header-bit + content and prefix it
    state.start -= 8
    cenc.uint32.encode(state, crc32(state.buffer.subarray(state.start + 4, state.start + 8 + len)))
    state.start += len + 4
  }

  _decodeEntry (state, enc) {
    if (state.end - state.start < 8) return null
    const cksum = cenc.uint32.decode(state)
    const l = cenc.uint32.decode(state)
    const length = l >>> 2
    const headerBit = l & 1
    const partialBit = l & 2

    if (state.end - state.start < length) return null

    const end = state.start + length

    if (crc32(state.buffer.subarray(state.start - 4, end)) !== cksum) {
      return null
    }

    const result = { header: headerBit, partial: partialBit !== 0, byteLength: length + 8, message: null }

    try {
      result.message = enc.decode({ start: state.start, end, buffer: state.buffer })
    } catch {
      return null
    }

    state.start = end

    return result
  }

  async open () {
    const buffer = await this._readAll() // TODO: stream the oplog in on load maybe?
    const state = { start: 0, end: buffer.byteLength, buffer }
    const result = { header: null, entries: [] }

    this.byteLength = 0
    this.length = 0

    const h1 = this._decodeEntry(state, this.headerEncoding)
    state.start = this._pageSize

    const h2 = this._decodeEntry(state, this.headerEncoding)
    state.start = this._entryOffset

    if (!h1 && !h2) {
      // reset state...
      this.flushed = false
      this._headers[0] = 1
      this._headers[1] = 0

      if (buffer.byteLength >= this._entryOffset) {
        throw OPLOG_CORRUPT()
      }
      return result
    }

    this.flushed = true

    if (h1 && !h2) {
      this._headers[0] = h1.header
      this._headers[1] = h1.header
    } else if (!h1 && h2) {
      this._headers[0] = (h2.header + 1) & 1
      this._headers[1] = h2.header
    } else {
      this._headers[0] = h1.header
      this._headers[1] = h2.header
    }

    const header = (this._headers[0] + this._headers[1]) & 1
    const decoded = []

    result.header = header ? h2.message : h1.message

    while (true) {
      const entry = this._decodeEntry(state, this.entryEncoding)
      if (!entry) break
      if (entry.header !== header) break

      decoded.push(entry)
    }

    while (decoded.length > 0 && decoded[decoded.length - 1].partial) decoded.pop()

    for (const e of decoded) {
      result.entries.push(e.message)
      this.byteLength += e.byteLength
      this.length++
    }

    const size = this.byteLength + this._entryOffset

    if (size === buffer.byteLength) return result

    await new Promise((resolve, reject) => {
      if (this.readonly) return resolve()
      this.storage.truncate(size, err => {
        if (err) return reject(err)
        resolve()
      })
    })

    return result
  }

  _readAll () {
    return new Promise((resolve, reject) => {
      this.storage.open(err => {
        if (err && err.code !== 'ENOENT') return reject(err)
        if (err) return resolve(b4a.alloc(0))
        this.storage.stat((err, stat) => {
          if (err && err.code !== 'ENOENT') return reject(err)
          this.storage.read(0, stat.size, (err, buf) => {
            if (err) return reject(err)
            resolve(buf)
          })
        })
      })
    })
  }

  flush (header) {
    const state = { start: 8, end: 8, buffer: null }
    const i = this._headers[0] === this._headers[1] ? 1 : 0
    const bit = (this._headers[i] + 1) & 1

    this.headerEncoding.preencode(state, header)
    if (state.end > this._pageSize) throw OPLOG_HEADER_OVERFLOW()
    state.buffer = b4a.allocUnsafe(state.end)
    this.headerEncoding.encode(state, header)
    this._addHeader(state, state.end - 8, bit, 0)

    return this._writeHeaderAndTruncate(i, bit, state.buffer)
  }

  _writeHeaderAndTruncate (i, bit, buf) {
    return new Promise((resolve, reject) => {
      this.storage.write(i === 0 ? 0 : this._pageSize, buf, err => {
        if (err) return reject(err)

        this.storage.truncate(this._entryOffset, err => {
          if (err) return reject(err)

          this._headers[i] = bit
          this.byteLength = 0
          this.length = 0
          this.flushed = true

          resolve()
        })
      })
    })
  }

  append (batch, atomic = true) {
    if (!Array.isArray(batch)) batch = [batch]

    const state = { start: 0, end: batch.length * 8, buffer: null }
    const bit = (this._headers[0] + this._headers[1]) & 1

    for (let i = 0; i < batch.length; i++) {
      this.entryEncoding.preencode(state, batch[i])
    }

    state.buffer = b4a.allocUnsafe(state.end)

    for (let i = 0; i < batch.length; i++) {
      const start = state.start += 8 // space for header
      const partial = (atomic && i < batch.length - 1) ? 2 : 0
      this.entryEncoding.encode(state, batch[i])
      this._addHeader(state, state.start - start, bit, partial)
    }

    return this._append(state.buffer, batch.length)
  }

  close () {
    return new Promise((resolve, reject) => {
      this.storage.close(err => {
        if (err) return reject(err)
        resolve()
      })
    })
  }

  _append (buf, count) {
    return new Promise((resolve, reject) => {
      this.storage.write(this._entryOffset + this.byteLength, buf, err => {
        if (err) return reject(err)

        this.byteLength += buf.byteLength
        this.length += count

        resolve()
      })
    })
  }
}

},{"b4a":4,"compact-encoding":16,"crc-universal":20,"hypercore-errors":27}],46:[function(require,module,exports){
const FIFO = require('fast-fifo')

module.exports = class ReceiverQueue {
  constructor () {
    this.queue = new FIFO()
    this.priority = []
    this.requests = new Map()
    this.length = 0
  }

  push (req) {
    // TODO: use a heap at some point if we wanna support multiple prios
    if (req.priority > 0) this.priority.push(req)
    else this.queue.push(req)

    this.requests.set(req.id, req)
    this.length++
  }

  shift () {
    while (this.priority.length > 0) {
      const msg = this.priority.pop()
      const req = this._processRequest(msg)
      if (req !== null) return req
    }

    while (this.queue.length > 0) {
      const msg = this.queue.shift()
      const req = this._processRequest(msg)
      if (req !== null) return req
    }

    return null
  }

  _processRequest (req) {
    if (req.block || req.hash || req.seek || req.upgrade || req.manifest) {
      this.requests.delete(req.id)
      this.length--
      return req
    }

    return null
  }

  delete (id) {
    const req = this.requests.get(id)
    if (!req) return

    req.block = null
    req.hash = null
    req.seek = null
    req.upgrade = null
    req.manifest = false

    this.requests.delete(id)
    this.length--

    if (this.length === 0) {
      this.queue.clear()
      this.priority = []
    }
  }
}

},{"fast-fifo":24}],47:[function(require,module,exports){
const BigSparseArray = require('big-sparse-array')
const quickbit = require('./compat').quickbit

const BITS_PER_PAGE = 32768
const BYTES_PER_PAGE = BITS_PER_PAGE / 8
const WORDS_PER_PAGE = BYTES_PER_PAGE / 4
const BITS_PER_SEGMENT = 2097152
const BYTES_PER_SEGMENT = BITS_PER_SEGMENT / 8
const PAGES_PER_SEGMENT = BITS_PER_SEGMENT / BITS_PER_PAGE

class RemoteBitfieldPage {
  constructor (index, bitfield, segment) {
    this.index = index
    this.offset = index * BYTES_PER_PAGE - segment.offset
    this.bitfield = bitfield
    this.segment = segment

    segment.add(this)
  }

  get tree () {
    return this.segment.tree
  }

  get (index) {
    return quickbit.get(this.bitfield, index)
  }

  set (index, val) {
    if (quickbit.set(this.bitfield, index, val)) {
      this.tree.update(this.offset * 8 + index)
    }
  }

  setRange (start, length, val) {
    quickbit.fill(this.bitfield, val, start, start + length)

    let i = Math.floor(start / 128)
    const n = i + Math.ceil(length / 128)

    while (i <= n) this.tree.update(this.offset * 8 + i++ * 128)
  }

  findFirst (val, position) {
    return quickbit.findFirst(this.bitfield, val, position)
  }

  findLast (val, position) {
    return quickbit.findLast(this.bitfield, val, position)
  }

  insert (start, bitfield) {
    this.bitfield.set(bitfield, start / 32)
    this.segment.refresh()
  }

  clear (start, bitfield) {
    quickbit.clear(this.bitfield, { field: bitfield, offset: start })
  }
}

class RemoteBitfieldSegment {
  constructor (index) {
    this.index = index
    this.offset = index * BYTES_PER_SEGMENT
    this.tree = quickbit.Index.from([], BYTES_PER_SEGMENT)
    this.pages = new Array(PAGES_PER_SEGMENT)
    this.pagesLength = 0
  }

  get chunks () {
    return this.tree.chunks
  }

  refresh () {
    this.tree = quickbit.Index.from(this.tree.chunks, BYTES_PER_SEGMENT)
  }

  add (page) {
    const pageIndex = page.index - this.index * PAGES_PER_SEGMENT
    if (pageIndex >= this.pagesLength) this.pagesLength = pageIndex + 1

    this.pages[pageIndex] = page

    const chunk = { field: page.bitfield, offset: page.offset }

    this.chunks.push(chunk)

    for (let i = this.chunks.length - 2; i >= 0; i--) {
      const prev = this.chunks[i]
      if (prev.offset <= chunk.offset) break
      this.chunks[i] = chunk
      this.chunks[i + 1] = prev
    }
  }

  findFirst (val, position) {
    position = this.tree.skipFirst(!val, position)

    let j = position & (BITS_PER_PAGE - 1)
    let i = (position - j) / BITS_PER_PAGE

    if (i >= PAGES_PER_SEGMENT) return -1

    while (i < this.pagesLength) {
      const p = this.pages[i]

      let index = -1

      if (p) index = p.findFirst(val, j)
      else if (!val) index = j

      if (index !== -1) return i * BITS_PER_PAGE + index

      j = 0
      i++
    }

    return -1
  }

  findLast (val, position) {
    position = this.tree.skipLast(!val, position)

    let j = position & (BITS_PER_PAGE - 1)
    let i = (position - j) / BITS_PER_PAGE

    if (i >= PAGES_PER_SEGMENT) return -1

    while (i >= 0) {
      const p = this.pages[i]

      let index = -1

      if (p) index = p.findLast(val, j)
      else if (!val) index = j

      if (index !== -1) return i * BITS_PER_PAGE + index

      j = BITS_PER_PAGE - 1
      i--
    }

    return -1
  }
}

module.exports = class RemoteBitfield {
  constructor () {
    this._pages = new BigSparseArray()
    this._segments = new BigSparseArray()
    this._maxSegments = 0
  }

  getBitfield (index) {
    const j = index & (BITS_PER_PAGE - 1)
    const i = (index - j) / BITS_PER_PAGE

    const p = this._pages.get(i)
    return p || null
  }

  get (index) {
    const j = index & (BITS_PER_PAGE - 1)
    const i = (index - j) / BITS_PER_PAGE

    const p = this._pages.get(i)

    return p ? p.get(j) : false
  }

  set (index, val) {
    const j = index & (BITS_PER_PAGE - 1)
    const i = (index - j) / BITS_PER_PAGE

    let p = this._pages.get(i)

    if (!p && val) {
      const k = Math.floor(i / PAGES_PER_SEGMENT)
      const s = this._segments.get(k) || this._segments.set(k, new RemoteBitfieldSegment(k))
      if (this._maxSegments <= k) this._maxSegments = k + 1

      p = this._pages.set(i, new RemoteBitfieldPage(i, new Uint32Array(WORDS_PER_PAGE), s))
    }

    if (p) p.set(j, val)
  }

  setRange (start, length, val) {
    let j = start & (BITS_PER_PAGE - 1)
    let i = (start - j) / BITS_PER_PAGE

    while (length > 0) {
      let p = this._pages.get(i)

      if (!p && val) {
        const k = Math.floor(i / PAGES_PER_SEGMENT)
        const s = this._segments.get(k) || this._segments.set(k, new RemoteBitfieldSegment(k))
        if (this._maxSegments <= k) this._maxSegments = k + 1

        p = this._pages.set(i, new RemoteBitfieldPage(i, new Uint32Array(WORDS_PER_PAGE), s))
      }

      const end = Math.min(j + length, BITS_PER_PAGE)
      const range = end - j

      if (p) p.setRange(j, range, val)

      j = 0
      i++
      length -= range
    }
  }

  findFirst (val, position) {
    let j = position & (BITS_PER_SEGMENT - 1)
    let i = (position - j) / BITS_PER_SEGMENT

    while (i < this._maxSegments) {
      const s = this._segments.get(i)

      let index = -1

      if (s) index = s.findFirst(val, j)
      else if (!val) index = j

      if (index !== -1) return i * BITS_PER_SEGMENT + index

      j = 0
      i++
    }

    return val ? -1 : position
  }

  firstSet (position) {
    return this.findFirst(true, position)
  }

  firstUnset (position) {
    return this.findFirst(false, position)
  }

  findLast (val, position) {
    let j = position & (BITS_PER_SEGMENT - 1)
    let i = (position - j) / BITS_PER_SEGMENT

    while (i >= 0) {
      const s = this._segments.get(i)

      let index = -1

      if (s) index = s.findLast(val, j)
      else if (!val) index = j

      if (index !== -1) return i * BITS_PER_SEGMENT + index

      j = BITS_PER_SEGMENT - 1
      i--
    }

    return -1
  }

  lastSet (position) {
    return this.findLast(true, position)
  }

  lastUnset (position) {
    return this.findLast(false, position)
  }

  insert (start, bitfield) {
    if (start % 32 !== 0) return false

    let length = bitfield.byteLength * 8

    let j = start & (BITS_PER_PAGE - 1)
    let i = (start - j) / BITS_PER_PAGE

    while (length > 0) {
      let p = this._pages.get(i)

      if (!p) {
        const k = Math.floor(i / PAGES_PER_SEGMENT)
        const s = this._segments.get(k) || this._segments.set(k, new RemoteBitfieldSegment(k))
        if (this._maxSegments <= k) this._maxSegments = k + 1

        p = this._pages.set(i, new RemoteBitfieldPage(i, new Uint32Array(WORDS_PER_PAGE), s))
      }

      const end = Math.min(j + length, BITS_PER_PAGE)
      const range = end - j

      p.insert(j, bitfield.subarray(0, range / 32))

      bitfield = bitfield.subarray(range / 32)

      j = 0
      i++
      length -= range
    }

    return true
  }

  clear (start, bitfield) {
    if (start % 32 !== 0) return false

    let length = bitfield.byteLength * 8

    let j = start & (BITS_PER_PAGE - 1)
    let i = (start - j) / BITS_PER_PAGE

    while (length > 0) {
      let p = this._pages.get(i)

      if (!p) {
        const k = Math.floor(i / PAGES_PER_SEGMENT)
        const s = this._segments.get(k) || this._segments.set(k, new RemoteBitfieldSegment(k))
        if (this._maxSegments <= k) this._maxSegments = k + 1

        p = this._pages.set(i, new RemoteBitfieldPage(i, new Uint32Array(WORDS_PER_PAGE), s))
      }

      const end = Math.min(j + length, BITS_PER_PAGE)
      const range = end - j

      p.clear(j, bitfield.subarray(0, range / 32))

      bitfield = bitfield.subarray(range / 32)

      j = 0
      i++
      length -= range
    }

    return true
  }
}

},{"./compat":36,"big-sparse-array":10}],48:[function(require,module,exports){
const b4a = require('b4a')
const safetyCatch = require('safety-catch')
const RandomIterator = require('random-array-iterator')
const flatTree = require('flat-tree')
const ReceiverQueue = require('./receiver-queue')
const RemoteBitfield = require('./remote-bitfield')
const { REQUEST_CANCELLED, REQUEST_TIMEOUT, INVALID_CAPABILITY, SNAPSHOT_NOT_AVAILABLE } = require('hypercore-errors')
const m = require('./messages')
const caps = require('./caps')

const DEFAULT_MAX_INFLIGHT = [32, 512]
const SCALE_LATENCY = 50
const DEFAULT_SEGMENT_SIZE = 256 * 1024 * 8 // 256 KiB in bits
const NOT_DOWNLOADING_SLACK = 4000 + (Math.random() * 4000) | 0

const PRIORITY = {
  NORMAL: 0,
  HIGH: 1,
  VERY_HIGH: 2
}

class Attachable {
  constructor () {
    this.resolved = false
    this.refs = []
  }

  attach (session) {
    const r = {
      context: this,
      session,
      sindex: 0,
      rindex: 0,
      snapshot: true,
      resolve: null,
      reject: null,
      promise: null,
      timeout: null
    }

    r.sindex = session.push(r) - 1
    r.rindex = this.refs.push(r) - 1
    r.promise = new Promise((resolve, reject) => {
      r.resolve = resolve
      r.reject = reject
    })

    return r
  }

  detach (r, err = null) {
    if (r.context !== this) return false

    this._detach(r)
    this._cancel(r, err)
    this.gc()

    return true
  }

  _detach (r) {
    const rh = this.refs.pop()
    const sh = r.session.pop()

    if (r.rindex < this.refs.length) this.refs[rh.rindex = r.rindex] = rh
    if (r.sindex < r.session.length) r.session[sh.sindex = r.sindex] = sh

    destroyRequestTimeout(r)
    r.context = null

    return r
  }

  gc () {
    if (this.refs.length === 0) this._unref()
  }

  _cancel (r, err) {
    r.reject(err || REQUEST_CANCELLED())
  }

  _unref () {
    // overwrite me
  }

  resolve (val) {
    this.resolved = true
    while (this.refs.length > 0) {
      this._detach(this.refs[this.refs.length - 1]).resolve(val)
    }
  }

  reject (err) {
    this.resolved = true
    while (this.refs.length > 0) {
      this._detach(this.refs[this.refs.length - 1]).reject(err)
    }
  }

  setTimeout (r, ms) {
    destroyRequestTimeout(r)
    r.timeout = setTimeout(onrequesttimeout, ms, r)
  }
}

class BlockRequest extends Attachable {
  constructor (tracker, index, priority) {
    super()

    this.index = index
    this.priority = priority
    this.inflight = []
    this.queued = false
    this.tracker = tracker
  }

  _unref () {
    for (const req of this.inflight) {
      req.peer._cancelRequest(req.id)
    }

    this.tracker.remove(this.index)
  }
}

class RangeRequest extends Attachable {
  constructor (ranges, start, end, linear, ifAvailable, blocks) {
    super()

    this.start = start
    this.end = end
    this.linear = linear
    this.ifAvailable = ifAvailable
    this.blocks = blocks
    this.ranges = ranges

    // As passed by the user, immut
    this.userStart = start
    this.userEnd = end
  }

  _unref () {
    const i = this.ranges.indexOf(this)
    if (i === -1) return
    const h = this.ranges.pop()
    if (i < this.ranges.length) this.ranges[i] = h
  }

  _cancel (r) {
    r.resolve(false)
  }
}

class UpgradeRequest extends Attachable {
  constructor (replicator, fork, length) {
    super()

    this.fork = fork
    this.length = length
    this.inflight = []
    this.replicator = replicator
  }

  _unref () {
    if (this.replicator.eagerUpgrade === true || this.inflight.length > 0) return
    this.replicator._upgrade = null
  }

  _cancel (r) {
    r.resolve(false)
  }
}

class SeekRequest extends Attachable {
  constructor (seeks, seeker) {
    super()

    this.seeker = seeker
    this.inflight = []
    this.seeks = seeks
  }

  _unref () {
    if (this.inflight.length > 0) return
    const i = this.seeks.indexOf(this)
    if (i === -1) return
    const h = this.seeks.pop()
    if (i < this.seeks.length) this.seeks[i] = h
  }
}

class InflightTracker {
  constructor () {
    this._requests = []
    this._free = []
  }

  get idle () {
    return this._requests.length === this._free.length
  }

  * [Symbol.iterator] () {
    for (const req of this._requests) {
      if (req !== null) yield req
    }
  }

  add (req) {
    const id = this._free.length ? this._free.pop() : this._requests.push(null)

    req.id = id
    this._requests[id - 1] = req
    return req
  }

  get (id) {
    return id <= this._requests.length ? this._requests[id - 1] : null
  }

  remove (id) {
    if (id <= this._requests.length) {
      const req = this._requests[id - 1]
      clearTimeout(req.timeout)
      req.timeout = null
      this._requests[id - 1] = null
      this._free.push(id)
    }
  }
}

class BlockTracker {
  constructor () {
    this._map = new Map()
  }

  [Symbol.iterator] () {
    return this._map.values()
  }

  isEmpty () {
    return this._map.size === 0
  }

  has (index) {
    return this._map.has(index)
  }

  get (index) {
    return this._map.get(index) || null
  }

  add (index, priority) {
    let b = this._map.get(index)
    if (b) return b

    b = new BlockRequest(this, index, priority)
    this._map.set(index, b)

    return b
  }

  remove (index) {
    const b = this.get(index)
    this._map.delete(index)
    return b
  }
}

class Peer {
  constructor (replicator, protomux, channel, session) {
    this.core = replicator.core
    this.replicator = replicator
    this.stream = protomux.stream
    this.protomux = protomux
    this.remotePublicKey = this.stream.remotePublicKey
    this.remoteSupportsSeeks = false

    this.paused = false

    this.session = session

    this.channel = channel
    this.channel.userData = this

    this.wireSync = this.channel.messages[0]
    this.wireRequest = this.channel.messages[1]
    this.wireCancel = this.channel.messages[2]
    this.wireData = this.channel.messages[3]
    this.wireNoData = this.channel.messages[4]
    this.wireWant = this.channel.messages[5]
    this.wireUnwant = this.channel.messages[6]
    this.wireBitfield = this.channel.messages[7]
    this.wireRange = this.channel.messages[8]
    this.wireExtension = this.channel.messages[9]

    this.receiverQueue = new ReceiverQueue()
    this.receiverBusy = false

    this.inflight = 0
    this.inflightRange = DEFAULT_MAX_INFLIGHT
    this.dataProcessing = 0

    this.canUpgrade = true

    this.needsSync = false
    this.syncsProcessing = 0

    // TODO: tweak pipelining so that data sent BEFORE remoteOpened is not cap verified!
    // we might wanna tweak that with some crypto, ie use the cap to encrypt it...
    // or just be aware of that, to only push non leaky data

    this.remoteOpened = false
    this.remoteBitfield = new RemoteBitfield()
    this.missingBlocks = new RemoteBitfield()

    this.remoteFork = 0
    this.remoteLength = 0
    this.remoteCanUpgrade = false
    this.remoteUploading = true
    this.remoteDownloading = true
    this.remoteSynced = false
    this.remoteHasManifest = false

    this.segmentsWanted = new Set()
    this.broadcastedNonSparse = false

    this.lengthAcked = 0

    this.extensions = new Map()
    this.lastExtensionSent = ''
    this.lastExtensionRecv = ''

    replicator._ifAvailable++
  }

  get remoteContiguousLength () {
    return this.remoteBitfield.findFirst(false, 0)
  }

  getMaxInflight () {
    const stream = this.stream.rawStream
    if (!stream.udx) return Math.min(this.inflightRange[1], this.inflightRange[0] * 3)

    const scale = stream.rtt <= SCALE_LATENCY ? 1 : stream.rtt / SCALE_LATENCY
    return Math.round(Math.min(this.inflightRange[1], this.inflightRange[0] * scale))
  }

  signalUpgrade () {
    if (this._shouldUpdateCanUpgrade() === true) this._updateCanUpgradeAndSync()
    else this.sendSync()
  }

  broadcastRange (start, length, drop) {
    if (drop) this._unclearLocalRange(start, length)
    else this._clearLocalRange(start, length)

    this.wireRange.send({
      drop,
      start,
      length
    })
  }

  extension (name, message) {
    this.wireExtension.send({ name: name === this.lastExtensionSent ? '' : name, message })
    this.lastExtensionSent = name
  }

  onextension (message) {
    const name = message.name || this.lastExtensionRecv
    this.lastExtensionRecv = name
    const ext = this.extensions.get(name)
    if (ext) ext._onmessage({ start: 0, end: message.byteLength, buffer: message.message }, this)
  }

  sendSync () {
    if (this.syncsProcessing !== 0) {
      this.needsSync = true
      return
    }

    if (this.core.tree.fork !== this.remoteFork) {
      this.canUpgrade = false
    }

    this.needsSync = false

    this.wireSync.send({
      fork: this.core.tree.fork,
      length: this.core.tree.length,
      remoteLength: this.core.tree.fork === this.remoteFork ? this.remoteLength : 0,
      canUpgrade: this.canUpgrade,
      uploading: true,
      downloading: this.replicator.isDownloading(),
      hasManifest: !!this.core.header.manifest && this.core.compat === false
    })
  }

  onopen ({ seeks, capability }) {
    const expected = caps.replicate(this.stream.isInitiator === false, this.replicator.key, this.stream.handshakeHash)

    if (b4a.equals(capability, expected) !== true) { // TODO: change this to a rejection instead, less leakage
      throw INVALID_CAPABILITY('Remote sent an invalid replication capability')
    }

    if (this.remoteOpened === true) return
    this.remoteOpened = true
    this.remoteSupportsSeeks = seeks

    this.protomux.cork()

    this.sendSync()

    const contig = Math.min(this.core.tree.length, this.core.header.hints.contiguousLength)
    if (contig > 0) {
      this.broadcastRange(0, contig, false)

      if (contig === this.core.tree.length) {
        this.broadcastedNonSparse = true
      }
    }

    this.replicator._ifAvailable--
    this.replicator._addPeer(this)

    this.protomux.uncork()
  }

  onclose (isRemote) {
    // we might have signalled to the remote that we are done (ie not downloading) and the remote might agree on that
    // if that happens, the channel might be closed by the remote. if so just renegotiate it.
    // TODO: add a CLOSE_REASON to mux to we can make this cleaner...
    const reopen = isRemote === true && this.remoteOpened === true && this.remoteDownloading === false &&
       this.remoteUploading === true && this.replicator.downloading === true

    if (this.session && !reopen) this.replicator._closeSession(this.session)

    if (this.remoteOpened === false) {
      this.replicator._ifAvailable--
      this.replicator.updateAll()
      return
    }

    this.remoteOpened = false
    this.replicator._removePeer(this)

    if (reopen) {
      this.replicator._makePeer(this.protomux, this.session)
    }
  }

  closeIfIdle () {
    if (this.remoteDownloading === false && this.replicator.isDownloading() === false) {
      // idling, shut it down...
      this.channel.close()
      return true
    }

    return false
  }

  async onsync ({ fork, length, remoteLength, canUpgrade, uploading, downloading, hasManifest }) {
    const lengthChanged = length !== this.remoteLength
    const sameFork = fork === this.core.tree.fork

    this.remoteSynced = true
    this.remoteFork = fork
    this.remoteLength = length
    this.remoteCanUpgrade = canUpgrade
    this.remoteUploading = uploading
    this.remoteDownloading = downloading
    this.remoteHasManifest = hasManifest

    if (this.closeIfIdle()) return

    this.lengthAcked = sameFork ? remoteLength : 0
    this.syncsProcessing++

    this.replicator._updateFork(this)

    if (this.remoteLength > this.core.tree.length && this.lengthAcked === this.core.tree.length) {
      if (this.replicator._addUpgradeMaybe() !== null) this._update()
    }

    const upgrade = (lengthChanged === false || sameFork === false)
      ? this.canUpgrade && sameFork
      : await this._canUpgrade(length, fork)

    if (length === this.remoteLength && fork === this.core.tree.fork) {
      this.canUpgrade = upgrade
    }

    if (--this.syncsProcessing !== 0) return // ie not latest

    if (this.needsSync === true || (this.core.tree.fork === this.remoteFork && this.core.tree.length > this.remoteLength)) {
      this.signalUpgrade()
    }

    this._update()
  }

  _shouldUpdateCanUpgrade () {
    return this.core.tree.fork === this.remoteFork &&
      this.core.tree.length > this.remoteLength &&
      this.canUpgrade === false &&
      this.syncsProcessing === 0
  }

  async _updateCanUpgradeAndSync () {
    const { length, fork } = this.core.tree

    const canUpgrade = await this._canUpgrade(this.remoteLength, this.remoteFork)

    if (this.syncsProcessing > 0 || length !== this.core.tree.length || fork !== this.core.tree.fork) {
      return
    }
    if (canUpgrade === this.canUpgrade) {
      return
    }

    this.canUpgrade = canUpgrade
    this.sendSync()
  }

  // Safe to call in the background - never fails
  async _canUpgrade (remoteLength, remoteFork) {
    if (remoteFork !== this.core.tree.fork) return false

    if (remoteLength === 0) return true
    if (remoteLength >= this.core.tree.length) return false

    try {
      // Rely on caching to make sure this is cheap...
      const canUpgrade = await this.core.tree.upgradeable(remoteLength)

      if (remoteFork !== this.core.tree.fork) return false

      return canUpgrade
    } catch {
      return false
    }
  }

  async _getProof (msg) {
    const proof = await this.core.tree.proof(msg)

    if (proof.block) {
      const index = msg.block.index

      if (msg.fork !== this.core.tree.fork || !this.core.bitfield.get(index)) {
        return null
      }

      proof.block.value = await this.core.blocks.get(index)
    }

    if (msg.manifest && !this.core.compat) {
      proof.manifest = this.core.header.manifest
    }

    return proof
  }

  async onrequest (msg) {
    if (!this.protomux.drained || this.receiverQueue.length) {
      this.receiverQueue.push(msg)
      return
    }

    await this._handleRequest(msg)
  }

  oncancel (msg) {
    this.receiverQueue.delete(msg.request)
  }

  ondrain () {
    return this._handleRequests()
  }

  async _handleRequests () {
    if (this.receiverBusy) return
    this.receiverBusy = true

    while (this.remoteOpened && this.protomux.drained && this.receiverQueue.length > 0) {
      const msg = this.receiverQueue.shift()
      await this._handleRequest(msg)
    }

    this.receiverBusy = false
  }

  async _handleRequest (msg) {
    let proof = null

    // TODO: could still be answerable if (index, fork) is an ancestor of the current fork
    if (msg.fork === this.core.tree.fork) {
      try {
        proof = await this._getProof(msg)
      } catch (err) {
        safetyCatch(err)
        if (msg.fork === this.core.tree.fork && isCriticalError(err)) throw err
      }
    }

    if (proof === null) {
      if (msg.manifest && this.core.header.manifest) {
        const manifest = this.core.header.manifest
        this.wireData.send({ request: msg.id, fork: this.core.tree.fork, block: null, hash: null, seek: null, upgrade: null, manifest })
        return
      }

      this.wireNoData.send({ request: msg.id })
      return
    }

    if (proof.block !== null) {
      this.replicator.onupload(proof.block.index, proof.block.value, this)
    }

    this.wireData.send({
      request: msg.id,
      fork: msg.fork,
      block: proof.block,
      hash: proof.hash,
      seek: proof.seek,
      upgrade: proof.upgrade,
      manifest: proof.manifest
    })
  }

  _cancelRequest (id) {
    const exists = this.replicator._inflight.get(id)
    if (!exists) return

    this.inflight--
    this.replicator._removeInflight(id)

    this.wireCancel.send({ request: id })
  }

  _checkIfConflict () {
    this.paused = true

    const length = Math.min(this.core.tree.length, this.remoteLength)
    if (length === 0) return // pause and ignore

    this.wireRequest.send({
      id: 0, // TODO: use an more explicit id for this eventually...
      fork: this.remoteFork,
      block: null,
      hash: null,
      seek: null,
      upgrade: {
        start: 0,
        length
      }
    })
  }

  async ondata (data) {
    // always allow a fork conflict proof to be sent
    if (data.request === 0 && data.upgrade && data.upgrade.start === 0) {
      if (await this.core.checkConflict(data, this)) return
      this.paused = false
    }

    const req = data.request > 0 ? this.replicator._inflight.get(data.request) : null
    const reorg = data.fork > this.core.tree.fork

    // no push atm, TODO: check if this satisfies another pending request
    // allow reorg pushes tho as those are not written to storage so we'll take all the help we can get
    if (req === null && reorg === false) return

    if (req !== null) {
      if (req.peer !== this) return
      this.inflight--
      this.replicator._removeInflight(req.id)
    }

    try {
      if (reorg === true) return await this.replicator._onreorgdata(this, req, data)
    } catch (err) {
      safetyCatch(err)
      this.paused = true
      this.replicator.oninvalid(err, req, data, this)
      return
    }

    this.dataProcessing++

    try {
      if (!matchingRequest(req, data) || !(await this.core.verify(data, this))) {
        this.replicator._onnodata(this, req)
        return
      }
    } catch (err) {
      safetyCatch(err)
      if (this.core.closed && !isCriticalError(err)) return

      if (err.code !== 'INVALID_OPERATION') {
        // might be a fork, verify
        this._checkIfConflict()
      }

      this.replicator._onnodata(this, req)
      this.replicator.oninvalid(err, req, data, this)
      return
    } finally {
      this.dataProcessing--
    }

    this.replicator._ondata(this, req, data)

    if (this._shouldUpdateCanUpgrade() === true) {
      this._updateCanUpgradeAndSync()
    }
  }

  onnodata ({ request }) {
    const req = request > 0 ? this.replicator._inflight.get(request) : null

    if (req === null || req.peer !== this) return

    this.inflight--
    this.replicator._removeInflight(req.id)
    this.replicator._onnodata(this, req)
  }

  onwant ({ start, length }) {
    this.replicator._onwant(this, start, length)
  }

  onunwant () {
    // TODO
  }

  onbitfield ({ start, bitfield }) {
    this.remoteBitfield.insert(start, bitfield)
    this.missingBlocks.insert(start, bitfield)
    this._clearLocalRange(start, bitfield.byteLength * 8)
    this._update()
  }

  _clearLocalRange (start, length) {
    if (length === 1) {
      this.missingBlocks.set(start, this.remoteBitfield.get(start) && !this.core.bitfield.get(start))
      return
    }

    const contig = Math.min(this.core.tree.length, this.core.header.hints.contiguousLength)

    if (start + length < contig) {
      const delta = contig - start
      this.missingBlocks.setRange(start, delta, false)
      return
    }

    const rem = start & 32767
    if (rem > 0) {
      start -= rem
      length += rem
    }

    const end = start + Math.min(length, this.core.tree.length)
    while (start < end) {
      const local = this.core.bitfield.getBitfield(start)

      if (local && local.bitfield) {
        this.missingBlocks.clear(start, local.bitfield)
      }

      start += 32768
    }
  }

  _unclearLocalRange (start, length) {
    if (length === 1) {
      this.missingBlocks.set(start, this.remoteBitfield.get(start) && !this.core.bitfield.get(start))
      return
    }

    const rem = start & 2097151
    if (rem > 0) {
      start -= rem
      length += rem
    }

    const fixedStart = start

    const end = start + Math.min(length, this.remoteLength)
    while (start < end) {
      const remote = this.remoteBitfield.getBitfield(start)
      if (remote && remote.bitfield) {
        this.missingBlocks.insert(start, remote.bitfield)
      }

      start += 2097152
    }

    this._clearLocalRange(fixedStart, length)
  }

  onrange ({ drop, start, length }) {
    const has = drop === false

    if (length === 1) {
      this.remoteBitfield.set(start, has)
      this.missingBlocks.set(start, has && !this.core.bitfield.get(start))
    } else {
      const rangeStart = this.remoteBitfield.findFirst(!has, start)
      const rangeLength = length - (rangeStart - start)

      if (rangeLength > 0) {
        this.remoteBitfield.setRange(rangeStart, rangeLength, has)
        this.missingBlocks.setRange(rangeStart, rangeLength, has)
        if (has) this._clearLocalRange(rangeStart, rangeLength)
      }
    }

    if (drop === false) this._update()
  }

  onreorghint () {
    // TODO
  }

  _update () {
    // TODO: if this is in a batch or similar it would be better to defer it
    // we could do that with nextTick/microtick mb? (combined with a property on the session to signal read buffer mb)
    this.replicator.updatePeer(this)
  }

  async _onconflict () {
    this.protomux.cork()
    if (this.remoteLength > 0 && this.core.tree.fork === this.remoteFork) {
      await this.onrequest({
        id: 0,
        fork: this.core.tree.fork,
        block: null,
        hash: null,
        seek: null,
        upgrade: {
          start: 0,
          length: Math.min(this.core.tree.length, this.remoteLength)
        }
      })
    }
    this.channel.close()
    this.protomux.uncork()
  }

  _makeRequest (needsUpgrade, priority) {
    if (needsUpgrade === true && this.replicator._shouldUpgrade(this) === false) {
      return null
    }

    if (needsUpgrade === false && this.replicator._autoUpgrade(this) === true) {
      needsUpgrade = true
    }

    return {
      peer: this,
      id: 0,
      fork: this.remoteFork,
      block: null,
      hash: null,
      seek: null,
      upgrade: needsUpgrade === false
        ? null
        : { start: this.core.tree.length, length: this.remoteLength - this.core.tree.length },
      // remote manifest check can be removed eventually...
      manifest: this.core.header.manifest === null && this.remoteHasManifest === true,
      priority
    }
  }

  _requestManifest () {
    const req = this._makeRequest(false, 0)
    this._send(req)
  }

  _requestUpgrade (u) {
    const req = this._makeRequest(true, 0)
    if (req === null) return false

    this._send(req)

    return true
  }

  _requestSeek (s) {
    // if replicator is updating the seeks etc, bail and wait for it to drain
    if (this.replicator._updatesPending > 0) return false

    const { length, fork } = this.core.tree

    if (fork !== this.remoteFork) return false

    if (s.seeker.start >= length) {
      const req = this._makeRequest(true, 0)

      // We need an upgrade for the seek, if non can be provided, skip
      if (req === null) return false

      req.seek = this.remoteSupportsSeeks ? { bytes: s.seeker.bytes, padding: s.seeker.padding } : null

      s.inflight.push(req)
      this._send(req)

      return true
    }

    const len = s.seeker.end - s.seeker.start
    const off = s.seeker.start + Math.floor(Math.random() * len)

    for (let i = 0; i < len; i++) {
      let index = off + i
      if (index > s.seeker.end) index -= len

      if (this.remoteBitfield.get(index) === false) continue
      if (this.core.bitfield.get(index) === true) continue
      if (!this._hasTreeParent(index)) continue

      // Check if this block is currently inflight - if so pick another
      const b = this.replicator._blocks.get(index)
      if (b !== null && b.inflight.length > 0) continue

      // Block is not inflight, but we only want the hash, check if that is inflight
      const h = this.replicator._hashes.add(index, PRIORITY.NORMAL)
      if (h.inflight.length > 0) continue

      const req = this._makeRequest(false, h.priority)
      const nodes = flatTree.depth(s.seeker.start + s.seeker.end - 1)

      req.hash = { index: 2 * index, nodes }
      req.seek = this.remoteSupportsSeeks ? { bytes: s.seeker.bytes, padding: s.seeker.padding } : null

      s.inflight.push(req)
      h.inflight.push(req)
      this._send(req)

      return true
    }

    this._maybeWant(s.seeker.start, len)
    return false
  }

  // mb turn this into a YES/NO/MAYBE enum, could simplify ifavail logic
  _blockAvailable (b) { // TODO: fork also
    return this.remoteBitfield.get(b.index)
  }

  _hasTreeParent (index) {
    if (this.remoteLength >= this.core.tree.length) return true

    const ite = flatTree.iterator(index * 2)

    let span = 2
    let length = 0

    while (true) {
      ite.parent()

      const left = (ite.index - ite.factor / 2 + 1) / 2
      length = left + span

      // if larger than local AND larger than remote - they share the root so its ok
      if (length > this.core.tree.length) {
        if (length > this.remoteLength) return true
        break
      }

      // its less than local but larger than remote so skip it
      if (length > this.remoteLength) break

      span *= 2
      const first = this.core.bitfield.findFirst(true, left)
      if (first > -1 && first < length) return true
    }

    // TODO: push to async queue and check against our local merkle tree if we actually can request this block
    return false
  }

  _requestBlock (b) {
    const { length, fork } = this.core.tree

    if (this.remoteBitfield.get(b.index) === false || fork !== this.remoteFork) {
      this._maybeWant(b.index)
      return false
    }
    if (!this._hasTreeParent(b.index)) {
      return false
    }

    const req = this._makeRequest(b.index >= length, b.priority)
    if (req === null) return false

    req.block = { index: b.index, nodes: 0 }

    b.inflight.push(req)
    this._send(req)

    return true
  }

  _requestRangeBlock (index, length) {
    if (this.core.bitfield.get(index) === true || !this._hasTreeParent(index)) return false

    const b = this.replicator._blocks.add(index, PRIORITY.NORMAL)
    if (b.inflight.length > 0) return false

    const req = this._makeRequest(index >= length, b.priority)

    // If the request cannot be satisfied, dealloc the block request if no one is subscribed to it
    if (req === null) {
      b.gc()
      return false
    }

    req.block = { index, nodes: 0 }

    b.inflight.push(req)
    this._send(req)

    // Don't think this will ever happen, as the pending queue is drained before the range queue
    // but doesn't hurt to check this explicitly here also.
    if (b.queued) b.queued = false
    return true
  }

  _requestRange (r) {
    const { length, fork } = this.core.tree

    if (r.blocks) {
      let min = -1
      let max = -1

      for (let i = r.start; i < r.end; i++) {
        const index = r.blocks[i]
        if (min === -1 || index < min) min = index
        if (max === -1 || index > max) max = index
        if (this.missingBlocks.get(index) === true && this._requestRangeBlock(index, length)) return true
      }

      if (min > -1) this._maybeWant(min, max - min)
      return false
    }

    const end = Math.min(r.end === -1 ? this.remoteLength : r.end, this.remoteLength)
    if (end < r.start || fork !== this.remoteFork) return false

    const len = end - r.start
    const off = r.start + (r.linear ? 0 : Math.floor(Math.random() * len))

    let i = off

    while (true) {
      i = this.missingBlocks.findFirst(true, i)
      if (i === -1 || i >= end) break

      if (this._requestRangeBlock(i, length)) return true
      i++
    }

    i = r.start

    while (true) {
      i = this.missingBlocks.findFirst(true, i)

      if (i === -1 || i >= off) break

      if (this._requestRangeBlock(i, length)) return true
      i++
    }

    this._maybeWant(r.start, len)
    return false
  }

  _requestForkProof (f) {
    const req = this._makeRequest(false, 0)

    req.upgrade = { start: 0, length: this.remoteLength }
    req.manifest = !this.core.header.manifest

    f.inflight.push(req)
    this._send(req)
  }

  _requestForkRange (f) {
    if (f.fork !== this.remoteFork || f.batch.want === null) return false

    const end = Math.min(f.batch.want.end, this.remoteLength)
    if (end < f.batch.want.start) return false

    const len = end - f.batch.want.start
    const off = f.batch.want.start + Math.floor(Math.random() * len)

    for (let i = 0; i < len; i++) {
      let index = off + i
      if (index >= end) index -= len

      if (this.remoteBitfield.get(index) === false) continue

      const req = this._makeRequest(false, 0)

      req.hash = { index: 2 * index, nodes: f.batch.want.nodes }

      f.inflight.push(req)
      this._send(req)

      return true
    }

    this._maybeWant(f.batch.want.start, len)
    return false
  }

  _maybeWant (start, length = 1) {
    if (start + length <= this.remoteContiguousLength) return

    let i = Math.floor(start / DEFAULT_SEGMENT_SIZE)
    const n = Math.ceil((start + length) / DEFAULT_SEGMENT_SIZE)

    for (; i < n; i++) {
      if (this.segmentsWanted.has(i)) continue
      this.segmentsWanted.add(i)

      this.wireWant.send({
        start: i * DEFAULT_SEGMENT_SIZE,
        length: DEFAULT_SEGMENT_SIZE
      })
    }
  }

  isActive () {
    if (this.paused || this.removed) return false
    return true
  }

  async _send (req) {
    const fork = this.core.tree.fork

    this.inflight++
    this.replicator._inflight.add(req)

    if (req.upgrade !== null && req.fork === fork) {
      const u = this.replicator._addUpgrade()
      u.inflight.push(req)
    }

    try {
      if (req.block !== null && req.fork === fork) {
        req.block.nodes = await this.core.tree.missingNodes(2 * req.block.index)
      }
      if (req.hash !== null && req.fork === fork && req.hash.nodes === 0) {
        req.hash.nodes = await this.core.tree.missingNodes(req.hash.index)

        // nodes === 0, we already have it, bail
        if (req.hash.nodes === 0 && (req.hash.index & 1) === 0) {
          this.inflight--
          this.replicator._resolveHashLocally(this, req)
          return
        }
      }
    } catch (err) {
      this.stream.destroy(err)
      return
    }

    this.wireRequest.send(req)
  }
}

module.exports = class Replicator {
  constructor (core, key, {
    notDownloadingLinger = NOT_DOWNLOADING_SLACK,
    eagerUpgrade = true,
    allowFork = true,
    onpeerupdate = noop,
    onupload = noop,
    oninvalid = noop
  } = {}) {
    this.key = key
    this.discoveryKey = core.crypto.discoveryKey(key)
    this.core = core
    this.eagerUpgrade = eagerUpgrade
    this.allowFork = allowFork
    this.onpeerupdate = onpeerupdate
    this.onupload = onupload
    this.oninvalid = oninvalid
    this.ondownloading = null // optional external hook for monitoring downloading status
    this.peers = []
    this.findingPeers = 0 // updateable from the outside
    this.destroyed = false
    this.downloading = true
    this.activeSessions = 0

    this._attached = new Set()
    this._inflight = new InflightTracker()
    this._blocks = new BlockTracker()
    this._hashes = new BlockTracker()

    this._queued = []

    this._seeks = []
    this._upgrade = null
    this._reorgs = []
    this._ranges = []

    this._hadPeers = false
    this._ifAvailable = 0
    this._updatesPending = 0
    this._applyingReorg = null
    this._manifestPeer = null
    this._notDownloadingLinger = notDownloadingLinger
    this._downloadingTimer = null

    const self = this
    this._onstreamclose = onstreamclose

    function onstreamclose () {
      self.detachFrom(this.userData)
    }
  }

  updateActivity (inc, session) {
    this.activeSessions += inc
    this.setDownloading(this.activeSessions !== 0, session)
  }

  isDownloading () {
    return this.downloading || !this._inflight.idle
  }

  setDownloading (downloading, session) {
    clearTimeout(this._downloadingTimer)

    if (this.destroyed) return
    if (downloading || this._notDownloadingLinger === 0) {
      this.setDownloadingNow(downloading, session)
      return
    }

    this._downloadingTimer = setTimeout(setDownloadingLater, this._notDownloadingLinger, this, downloading, session)
  }

  setDownloadingNow (downloading, session) {
    this._downloadingTimer = null
    if (this.downloading === downloading) return
    this.downloading = downloading
    if (!downloading && this.isDownloading()) return

    for (const peer of this.peers) peer.signalUpgrade()

    if (downloading) { // restart channel if needed...
      for (const protomux of this._attached) {
        if (!protomux.stream.handshakeHash) continue
        if (protomux.opened({ protocol: 'hypercore/alpha', id: this.discoveryKey })) continue
        this._makePeer(protomux, session && session.session({ active: false }))
      }
    } else {
      for (const peer of this.peers) peer.closeIfIdle()
    }

    if (this.ondownloading !== null && downloading) this.ondownloading()
  }

  cork () {
    for (const peer of this.peers) peer.protomux.cork()
  }

  uncork () {
    for (const peer of this.peers) peer.protomux.uncork()
  }

  // Called externally when a range of new blocks has been processed/removed
  onhave (start, length, drop = false) {
    for (const peer of this.peers) peer.broadcastRange(start, length, drop)
  }

  // Called externally when a truncation upgrade has been processed
  ontruncate (newLength, truncated) {
    const notify = []

    for (const blk of this._blocks) {
      if (blk.index < newLength) continue
      notify.push(blk)
    }

    for (const blk of notify) {
      for (const r of blk.refs) {
        if (r.snapshot === false) continue
        blk.detach(r, SNAPSHOT_NOT_AVAILABLE())
      }
    }

    for (const peer of this.peers) peer._unclearLocalRange(newLength, truncated)
  }

  // Called externally when a upgrade has been processed
  onupgrade () {
    for (const peer of this.peers) peer.signalUpgrade()
    if (this._blocks.isEmpty() === false) this._resolveBlocksLocally()
    if (this._upgrade !== null) this._resolveUpgradeRequest(null)
    if (this._ranges.length !== 0 || this._seeks.length !== 0) this._updateNonPrimary(true)
  }

  // Called externally when a conflict has been detected and verified
  async onconflict (from) {
    const all = []
    for (const peer of this.peers) {
      all.push(peer._onconflict())
    }
    await Promise.allSettled(all)
  }

  async applyPendingReorg () {
    if (this._applyingReorg !== null) {
      await this._applyingReorg
      return true
    }

    for (let i = this._reorgs.length - 1; i >= 0; i--) {
      const f = this._reorgs[i]
      if (f.batch !== null && f.batch.finished) {
        await this._applyReorg(f)
        return true
      }
    }

    return false
  }

  addUpgrade (session) {
    if (this._upgrade !== null) {
      const ref = this._upgrade.attach(session)
      this._checkUpgradeIfAvailable()
      return ref
    }

    const ref = this._addUpgrade().attach(session)

    this.updateAll()

    return ref
  }

  addBlock (session, index) {
    const b = this._blocks.add(index, PRIORITY.HIGH)
    const ref = b.attach(session)

    this._queueBlock(b)
    this.updateAll()

    return ref
  }

  addSeek (session, seeker) {
    const s = new SeekRequest(this._seeks, seeker)
    const ref = s.attach(session)

    this._seeks.push(s)
    this.updateAll()

    return ref
  }

  addRange (session, { start = 0, end = -1, length = toLength(start, end), blocks = null, linear = false, ifAvailable = false } = {}) {
    if (blocks !== null) { // if using blocks, start, end just acts as frames around the blocks array
      start = 0
      end = length = blocks.length
    }

    const r = new RangeRequest(
      this._ranges,
      start,
      length === -1 ? -1 : start + length,
      linear,
      ifAvailable,
      blocks
    )

    const ref = r.attach(session)

    this._ranges.push(r)

    // Trigger this to see if this is already resolved...
    // Also auto compresses the range based on local bitfield
    this._updateNonPrimary(true)

    return ref
  }

  cancel (ref) {
    ref.context.detach(ref, null)
  }

  clearRequests (session, err = null) {
    while (session.length > 0) {
      const ref = session[session.length - 1]
      ref.context.detach(ref, err)
    }

    this.updateAll()
  }

  _addUpgradeMaybe () {
    return this.eagerUpgrade === true ? this._addUpgrade() : this._upgrade
  }

  // TODO: this function is OVER called atm, at each updatePeer/updateAll
  // instead its more efficient to only call it when the conditions in here change - ie on sync/add/remove peer
  // Do this when we have more tests.
  _checkUpgradeIfAvailable () {
    if (this._ifAvailable > 0 || this._upgrade === null || this._upgrade.refs.length === 0) return
    if (this._hadPeers === false && this.findingPeers > 0) return

    // check if a peer can upgrade us

    for (let i = 0; i < this.peers.length; i++) {
      const peer = this.peers[i]

      if (peer.remoteSynced === false) return

      if (this.core.tree.length === 0 && peer.remoteLength > 0) return

      if (peer.remoteLength <= this._upgrade.length || peer.remoteFork !== this._upgrade.fork) continue

      if (peer.syncsProcessing > 0) return

      if (peer.lengthAcked !== this.core.tree.length && peer.remoteFork === this.core.tree.fork) return
      if (peer.remoteCanUpgrade === true) return
    }

    // check if reorgs in progress...

    if (this._applyingReorg !== null) return

    // TODO: we prob should NOT wait for inflight reorgs here, seems better to just resolve the upgrade
    // and then apply the reorg on the next call in case it's slow - needs some testing in practice

    for (let i = 0; i < this._reorgs.length; i++) {
      const r = this._reorgs[i]
      if (r.inflight.length > 0) return
    }

    // nothing to do, indicate no update avail

    const u = this._upgrade
    this._upgrade = null
    u.resolve(false)
  }

  _addUpgrade () {
    if (this._upgrade !== null) return this._upgrade

    // TODO: needs a reorg: true/false flag to indicate if the user requested a reorg
    this._upgrade = new UpgradeRequest(this, this.core.tree.fork, this.core.tree.length)

    return this._upgrade
  }

  _addReorg (fork, peer) {
    if (this.allowFork === false) return null

    // TODO: eager gc old reorgs from the same peer
    // not super important because they'll get gc'ed when the request finishes
    // but just spam the remote can do ...

    for (const f of this._reorgs) {
      if (f.fork > fork && f.batch !== null) return null
      if (f.fork === fork) return f
    }

    const f = {
      fork,
      inflight: [],
      batch: null
    }

    this._reorgs.push(f)

    // maintain sorted by fork
    let i = this._reorgs.length - 1
    while (i > 0 && this._reorgs[i - 1].fork > fork) {
      this._reorgs[i] = this._reorgs[i - 1]
      this._reorgs[--i] = f
    }

    return f
  }

  _shouldUpgrade (peer) {
    if (this._upgrade !== null && this._upgrade.inflight.length > 0) return false
    return peer.remoteCanUpgrade === true &&
      peer.remoteLength > this.core.tree.length &&
      peer.lengthAcked === this.core.tree.length
  }

  _autoUpgrade (peer) {
    return this._upgrade !== null && peer.remoteFork === this.core.tree.fork && this._shouldUpgrade(peer)
  }

  _addPeer (peer) {
    this._hadPeers = true
    this.peers.push(peer)
    this.updatePeer(peer)
    this.onpeerupdate(true, peer)
  }

  _removeInflight (id) {
    this._inflight.remove(id)
    if (this.isDownloading() === false) {
      for (const peer of this.peers) peer.signalUpgrade()
    }
  }

  _removePeer (peer) {
    this.peers.splice(this.peers.indexOf(peer), 1)
    peer.removed = true

    if (this._manifestPeer === peer) this._manifestPeer = null

    for (const req of this._inflight) {
      if (req.peer !== peer) continue
      this._inflight.remove(req.id)
      this._clearRequest(peer, req)
    }

    this.onpeerupdate(false, peer)
    this.updateAll()
  }

  _queueBlock (b) {
    if (b.inflight.length > 0 || b.queued === true) return
    b.queued = true
    this._queued.push(b)
  }

  _resolveHashLocally (peer, req) {
    this._removeInflight(req.id)
    this._resolveBlockRequest(this._hashes, req.hash.index / 2, null, req)
    this.updatePeer(peer)
  }

  // Runs in the background - not allowed to throw
  async _resolveBlocksLocally () {
    // TODO: check if fork compat etc. Requires that we pass down truncation info

    let clear = null

    for (const b of this._blocks) {
      if (this.core.bitfield.get(b.index) === false) continue

      try {
        b.resolve(await this.core.blocks.get(b.index))
      } catch (err) {
        b.reject(err)
      }

      if (clear === null) clear = []
      clear.push(b)
    }

    if (clear === null) return

    // Currently the block tracker does not support deletes during iteration, so we make
    // sure to clear them afterwards.
    for (const b of clear) {
      this._blocks.remove(b.index)
    }
  }

  _resolveBlockRequest (tracker, index, value, req) {
    const b = tracker.remove(index)
    if (b === null) return false

    removeInflight(b.inflight, req)
    b.queued = false

    b.resolve(value)

    return true
  }

  _resolveUpgradeRequest (req) {
    if (req !== null) removeInflight(this._upgrade.inflight, req)

    if (this.core.tree.length === this._upgrade.length && this.core.tree.fork === this._upgrade.fork) return false

    const u = this._upgrade
    this._upgrade = null
    u.resolve(true)

    return true
  }

  _resolveRangeRequest (req, index) {
    const head = this._ranges.pop()

    if (index < this._ranges.length) this._ranges[index] = head

    req.resolve(true)
  }

  _clearInflightBlock (tracker, req) {
    const isBlock = tracker === this._blocks
    const index = isBlock === true ? req.block.index : req.hash.index / 2
    const b = tracker.get(index)

    if (b === null || removeInflight(b.inflight, req) === false) return

    // if (isBlock && this.core.bitfield.get(index) === false) {
    //   for (const peer of this.peers) peer.skipList.set(index, false)
    // }

    if (b.refs.length > 0 && isBlock === true) {
      this._queueBlock(b)
      return
    }

    b.gc()
  }

  _clearInflightUpgrade (req) {
    if (removeInflight(this._upgrade.inflight, req) === false) return
    this._upgrade.gc()
  }

  _clearInflightSeeks (req) {
    for (const s of this._seeks) {
      if (removeInflight(s.inflight, req) === false) continue
      s.gc()
    }
  }

  _clearInflightReorgs (req) {
    for (const r of this._reorgs) {
      removeInflight(r.inflight, req)
    }
  }

  _clearOldReorgs (fork) {
    for (let i = 0; i < this._reorgs.length; i++) {
      const f = this._reorgs[i]
      if (f.fork >= fork) continue
      if (i === this._reorgs.length - 1) this._reorgs.pop()
      else this._reorgs[i] = this._reorgs.pop()
      i--
    }
  }

  // "slow" updates here - async but not allowed to ever throw
  async _updateNonPrimary (updateAll) {
    // Check if running, if so skip it and the running one will issue another update for us (debounce)
    while (++this._updatesPending === 1) {
      for (let i = 0; i < this._ranges.length; i++) {
        const r = this._ranges[i]

        clampRange(this.core, r)

        if (r.end !== -1 && r.start >= r.end) {
          this._resolveRangeRequest(r, i--)
        }
      }

      for (let i = 0; i < this._seeks.length; i++) {
        const s = this._seeks[i]

        let err = null
        let res = null

        try {
          res = await s.seeker.update()
        } catch (error) {
          err = error
        }

        if (!res && !err) continue

        if (i < this._seeks.length - 1) this._seeks[i] = this._seeks.pop()
        else this._seeks.pop()

        i--

        if (err) s.reject(err)
        else s.resolve(res)
      }

      // No additional updates scheduled - break
      if (--this._updatesPending === 0) break
      // Debounce the additional updates - continue
      this._updatesPending = 0
    }

    if (this._inflight.idle || updateAll) this.updateAll()
  }

  _maybeResolveIfAvailableRanges () {
    if (this._ifAvailable > 0 || !this._inflight.idle || !this._ranges.length) return

    for (let i = 0; i < this.peers.length; i++) {
      if (this.peers[i].dataProcessing > 0) return
    }

    for (let i = 0; i < this._ranges.length; i++) {
      const r = this._ranges[i]

      if (r.ifAvailable) {
        this._resolveRangeRequest(r, i--)
      }
    }
  }

  _clearRequest (peer, req) {
    if (req.block !== null) {
      this._clearInflightBlock(this._blocks, req)
    }

    if (req.hash !== null) {
      this._clearInflightBlock(this._hashes, req)
    }

    if (req.upgrade !== null && this._upgrade !== null) {
      this._clearInflightUpgrade(req)
    }

    if (this._seeks.length > 0) {
      this._clearInflightSeeks(req)
    }

    if (this._reorgs.length > 0) {
      this._clearInflightReorgs(req)
    }
  }

  _onnodata (peer, req) {
    this._clearRequest(peer, req)
    this.updateAll()
  }

  _ondata (peer, req, data) {
    if (data.block !== null) {
      this._resolveBlockRequest(this._blocks, data.block.index, data.block.value, req)
    }

    if (data.hash !== null && (data.hash.index & 1) === 0) {
      this._resolveBlockRequest(this._hashes, data.hash.index / 2, null, req)
    }

    if (this._upgrade !== null) {
      this._resolveUpgradeRequest(req)
    }

    if (this._seeks.length > 0) {
      this._clearInflightSeeks(req)
    }

    if (this._reorgs.length > 0) {
      this._clearInflightReorgs(req)
    }

    if (this._manifestPeer === peer && this.core.header.manifest !== null) {
      this._manifestPeer = null
    }

    if (this._seeks.length > 0 || this._ranges.length > 0) this._updateNonPrimary(this._seeks.length > 0)
    this.updatePeer(peer)
  }

  _onwant (peer, start, length) {
    length = Math.min(length, this.core.tree.length - start)

    peer.protomux.cork()

    for (const msg of this.core.bitfield.want(start, length)) {
      peer.wireBitfield.send(msg)
    }

    peer.protomux.uncork()
  }

  async _onreorgdata (peer, req, data) {
    const newBatch = data.upgrade && await this.core.verifyReorg(data)
    const f = this._addReorg(data.fork, peer)

    if (f === null) {
      this.updateAll()
      return
    }

    removeInflight(f.inflight, req)

    if (f.batch) {
      await f.batch.update(data)
    } else if (data.upgrade) {
      f.batch = newBatch

      // Remove "older" reorgs in progress as we just verified this one.
      this._clearOldReorgs(f.fork)
    }

    if (f.batch && f.batch.finished) {
      if (this._addUpgradeMaybe() !== null) {
        await this._applyReorg(f)
      }
    }

    this.updateAll()
  }

  // Never throws, allowed to run in the background
  async _applyReorg (f) {
    // TODO: more optimal here to check if potentially a better reorg
    // is available, ie higher fork, and request that one first.
    // This will request that one after this finishes, which is fine, but we
    // should investigate the complexity in going the other way

    const u = this._upgrade

    this._reorgs = [] // clear all as the nodes are against the old tree - easier
    this._applyingReorg = this.core.reorg(f.batch, null) // TODO: null should be the first/last peer?

    try {
      await this._applyingReorg
    } catch (err) {
      this._upgrade = null
      u.reject(err)
    }

    this._applyingReorg = null

    if (this._upgrade !== null) {
      this._resolveUpgradeRequest(null)
    }

    for (const peer of this.peers) this._updateFork(peer)

    // TODO: all the remaining is a tmp workaround until we have a flag/way for ANY_FORK
    for (const r of this._ranges) {
      r.start = r.userStart
      r.end = r.userEnd
    }

    this.updateAll()
  }

  _maybeUpdate () {
    return this._upgrade !== null && this._upgrade.inflight.length === 0
  }

  _maybeRequestManifest () {
    return this.core.header.manifest === null && this._manifestPeer === null
  }

  _updateFork (peer) {
    if (this._applyingReorg !== null || this.allowFork === false || peer.remoteFork <= this.core.tree.fork) {
      return false
    }

    const f = this._addReorg(peer.remoteFork, peer)

    // TODO: one per peer is better
    if (f !== null && f.batch === null && f.inflight.length === 0) {
      return peer._requestForkProof(f)
    }

    return false
  }

  _updatePeer (peer) {
    if (!peer.isActive() || peer.inflight >= peer.getMaxInflight()) {
      return false
    }

    // Eagerly request the manifest even if the remote length is 0. If not 0 we'll get as part of the upgrade request...
    if (this._maybeRequestManifest() === true && peer.remoteLength === 0 && peer.remoteHasManifest === true) {
      this._manifestPeer = peer
      peer._requestManifest()
    }

    for (const s of this._seeks) {
      if (s.inflight.length > 0) continue // TODO: one per peer is better
      if (peer._requestSeek(s) === true) {
        return true
      }
    }

    // Implied that any block in the queue should be requested, no matter how many inflights
    const blks = new RandomIterator(this._queued)

    for (const b of blks) {
      if (b.queued === false || peer._requestBlock(b) === true) {
        b.queued = false
        blks.dequeue()
        return true
      }
    }

    return false
  }

  _updatePeerNonPrimary (peer) {
    if (!peer.isActive() || peer.inflight >= peer.getMaxInflight()) {
      return false
    }

    const ranges = new RandomIterator(this._ranges)

    for (const r of ranges) {
      if (peer._requestRange(r) === true) {
        return true
      }
    }

    // Iterate from newest fork to oldest fork...
    for (let i = this._reorgs.length - 1; i >= 0; i--) {
      const f = this._reorgs[i]
      if (f.batch !== null && f.inflight.length === 0 && peer._requestForkRange(f) === true) {
        return true
      }
    }

    if (this._maybeUpdate() === true && peer._requestUpgrade(this._upgrade) === true) {
      return true
    }

    return false
  }

  updatePeer (peer) {
    // Quick shortcut to wait for flushing reorgs - not needed but less waisted requests
    if (this._applyingReorg !== null) return

    while (this._updatePeer(peer) === true);
    while (this._updatePeerNonPrimary(peer) === true);

    this._checkUpgradeIfAvailable()
    this._maybeResolveIfAvailableRanges()
  }

  updateAll () {
    // Quick shortcut to wait for flushing reorgs - not needed but less waisted requests
    if (this._applyingReorg !== null) return

    const peers = new RandomIterator(this.peers)

    for (const peer of peers) {
      if (this._updatePeer(peer) === true) {
        peers.requeue()
      }
    }

    // Check if we can skip the non primary check fully
    if (this._maybeUpdate() === false && this._ranges.length === 0 && this._reorgs.length === 0) {
      this._checkUpgradeIfAvailable()
      return
    }

    for (const peer of peers.restart()) {
      if (this._updatePeerNonPrimary(peer) === true) {
        peers.requeue()
      }
    }

    this._checkUpgradeIfAvailable()
    this._maybeResolveIfAvailableRanges()
  }

  _closeSession (session) {
    session.close().catch(noop)
  }

  attached (protomux) {
    return this._attached.has(protomux)
  }

  attachTo (protomux, session) {
    const makePeer = this._makePeer.bind(this, protomux, session)

    this._attached.add(protomux)
    protomux.pair({ protocol: 'hypercore/alpha', id: this.discoveryKey }, makePeer)
    protomux.stream.setMaxListeners(0)
    protomux.stream.on('close', this._onstreamclose)

    this._ifAvailable++
    protomux.stream.opened.then((opened) => {
      this._ifAvailable--

      if (opened && !this.destroyed) makePeer()
      else if (session) this._closeSession(session)
      this._checkUpgradeIfAvailable()
    })
  }

  detachFrom (protomux) {
    if (this._attached.delete(protomux)) {
      protomux.stream.removeListener('close', this._onstreamclose)
      protomux.unpair({ protocol: 'hypercore/alpha', id: this.discoveryKey })
    }
  }

  destroy () {
    this.destroyed = true
    if (this._downloadingTimer) {
      clearTimeout(this._downloadingTimer)
      this._downloadingTimer = null
    }
    for (const peer of this.peers) {
      this.detachFrom(peer.protomux)
      peer.channel.close()
    }
    for (const protomux of this._attached) {
      this.detachFrom(protomux)
    }
  }

  _makePeer (protomux, session) {
    const replicator = this
    if (protomux.opened({ protocol: 'hypercore/alpha', id: this.discoveryKey })) return onnochannel()

    const channel = protomux.createChannel({
      userData: null,
      protocol: 'hypercore/alpha',
      aliases: ['hypercore'],
      id: this.discoveryKey,
      handshake: m.wire.handshake,
      messages: [
        { encoding: m.wire.sync, onmessage: onwiresync },
        { encoding: m.wire.request, onmessage: onwirerequest },
        { encoding: m.wire.cancel, onmessage: onwirecancel },
        { encoding: m.wire.data, onmessage: onwiredata },
        { encoding: m.wire.noData, onmessage: onwirenodata },
        { encoding: m.wire.want, onmessage: onwirewant },
        { encoding: m.wire.unwant, onmessage: onwireunwant },
        { encoding: m.wire.bitfield, onmessage: onwirebitfield },
        { encoding: m.wire.range, onmessage: onwirerange },
        { encoding: m.wire.extension, onmessage: onwireextension }
      ],
      onopen: onwireopen,
      onclose: onwireclose,
      ondrain: onwiredrain
    })

    if (channel === null) return onnochannel()

    const peer = new Peer(replicator, protomux, channel, session)
    const stream = protomux.stream

    peer.channel.open({
      seeks: true,
      capability: caps.replicate(stream.isInitiator, this.key, stream.handshakeHash)
    })

    return true

    function onnochannel () {
      if (session) replicator._closeSession(session)
      return false
    }
  }
}

function matchingRequest (req, data) {
  if (data.block !== null && (req.block === null || req.block.index !== data.block.index)) return false
  if (data.hash !== null && (req.hash === null || req.hash.index !== data.hash.index)) return false
  if (data.seek !== null && (req.seek === null || req.seek.bytes !== data.seek.bytes)) return false
  if (data.upgrade !== null && req.upgrade === null) return false
  return req.fork === data.fork
}

function removeInflight (inf, req) {
  const i = inf.indexOf(req)
  if (i === -1) return false
  if (i < inf.length - 1) inf[i] = inf.pop()
  else inf.pop()
  return true
}

function noop () {}

function toLength (start, end) {
  return end === -1 ? -1 : (end < start ? 0 : end - start)
}

function clampRange (core, r) {
  if (r.blocks === null) {
    const start = core.bitfield.firstUnset(r.start)

    if (r.end === -1) r.start = start === -1 ? core.tree.length : start
    else if (start === -1 || start >= r.end) r.start = r.end
    else {
      r.start = start

      const end = core.bitfield.lastUnset(r.end - 1)

      if (end === -1 || start >= end + 1) r.end = r.start
      else r.end = end + 1
    }
  } else {
    while (r.start < r.end && core.bitfield.get(r.blocks[r.start])) r.start++
    while (r.start < r.end && core.bitfield.get(r.blocks[r.end - 1])) r.end--
  }
}

function onrequesttimeout (req) {
  if (req.context) req.context.detach(req, REQUEST_TIMEOUT())
}

function destroyRequestTimeout (req) {
  if (req.timeout !== null) {
    clearTimeout(req.timeout)
    req.timeout = null
  }
}

function isCriticalError (err) {
  // TODO: expose .critical or similar on the hypercore errors that are critical (if all not are)
  return err.name === 'HypercoreError'
}

function onwireopen (m, c) {
  return c.userData.onopen(m)
}

function onwireclose (isRemote, c) {
  return c.userData.onclose(isRemote)
}

function onwiredrain (c) {
  return c.userData.ondrain()
}

function onwiresync (m, c) {
  return c.userData.onsync(m)
}

function onwirerequest (m, c) {
  return c.userData.onrequest(m)
}

function onwirecancel (m, c) {
  return c.userData.oncancel(m)
}

function onwiredata (m, c) {
  return c.userData.ondata(m)
}

function onwirenodata (m, c) {
  return c.userData.onnodata(m)
}

function onwirewant (m, c) {
  return c.userData.onwant(m)
}

function onwireunwant (m, c) {
  return c.userData.onunwant(m)
}

function onwirebitfield (m, c) {
  return c.userData.onbitfield(m)
}

function onwirerange (m, c) {
  return c.userData.onrange(m)
}

function onwireextension (m, c) {
  return c.userData.onextension(m)
}

function setDownloadingLater (repl, downloading, session) {
  repl.setDownloadingNow(downloading, session)
}

},{"./caps":35,"./messages":42,"./receiver-queue":46,"./remote-bitfield":47,"b4a":4,"flat-tree":25,"hypercore-errors":27,"random-array-iterator":62,"safety-catch":65}],49:[function(require,module,exports){
const { Writable, Readable } = require('streamx')

class ReadStream extends Readable {
  constructor (core, opts = {}) {
    super()

    this.core = core
    this.start = opts.start || 0
    this.end = typeof opts.end === 'number' ? opts.end : -1
    this.snapshot = !opts.live && opts.snapshot !== false
    this.live = !!opts.live
  }

  _open (cb) {
    this._openP().then(cb, cb)
  }

  _read (cb) {
    this._readP().then(cb, cb)
  }

  async _openP () {
    if (this.end === -1) await this.core.update()
    else await this.core.ready()
    if (this.snapshot && this.end === -1) this.end = this.core.length
  }

  async _readP () {
    const end = this.live ? -1 : (this.end === -1 ? this.core.length : this.end)
    if (end >= 0 && this.start >= end) {
      this.push(null)
      return
    }

    this.push(await this.core.get(this.start++))
  }
}

exports.ReadStream = ReadStream

class WriteStream extends Writable {
  constructor (core) {
    super()
    this.core = core
  }

  _writev (batch, cb) {
    this._writevP(batch).then(cb, cb)
  }

  async _writevP (batch) {
    await this.core.append(batch)
  }
}

exports.WriteStream = WriteStream

class ByteStream extends Readable {
  constructor (core, opts = {}) {
    super()

    this._core = core
    this._index = 0
    this._range = null

    this._byteOffset = opts.byteOffset || 0
    this._byteLength = typeof opts.byteLength === 'number' ? opts.byteLength : -1
    this._prefetch = typeof opts.prefetch === 'number' ? opts.prefetch : 32

    this._applyOffset = this._byteOffset > 0
  }

  _open (cb) {
    this._openp().then(cb, cb)
  }

  _read (cb) {
    this._readp().then(cb, cb)
  }

  async _openp () {
    if (this._byteLength === -1) {
      await this._core.update()
      this._byteLength = Math.max(this._core.byteLength - this._byteOffset, 0)
    }
  }

  async _readp () {
    let data = null

    if (this._byteLength === 0) {
      this.push(null)
      return
    }

    let relativeOffset = 0

    if (this._applyOffset) {
      this._applyOffset = false

      const [block, byteOffset] = await this._core.seek(this._byteOffset)

      this._index = block
      relativeOffset = byteOffset
    }

    this._predownload(this._index + 1)
    data = await this._core.get(this._index++)

    if (relativeOffset > 0) data = data.subarray(relativeOffset)

    if (data.byteLength > this._byteLength) data = data.subarray(0, this._byteLength)
    this._byteLength -= data.byteLength

    this.push(data)
    if (this._byteLength === 0) this.push(null)
  }

  _predownload (index) {
    if (this._range) this._range.destroy()
    this._range = this._core.download({ start: index, end: index + this._prefetch, linear: true })
  }

  _destroy (cb) {
    if (this._range) this._range.destroy()
    cb(null)
  }
}

exports.ByteStream = ByteStream

},{"streamx":128}],50:[function(require,module,exports){
const b4a = require('b4a')

module.exports = function isOptions (opts) {
  return typeof opts === 'object' && opts && !b4a.isBuffer(opts)
}

},{"b4a":4}],51:[function(require,module,exports){
module.exports = assert

class AssertionError extends Error {}
AssertionError.prototype.name = 'AssertionError'

/**
 * Minimal assert function
 * @param  {any} t Value to check if falsy
 * @param  {string=} m Optional assertion error message
 * @throws {AssertionError}
 */
function assert (t, m) {
  if (!t) {
    var err = new AssertionError(m)
    if (Error.captureStackTrace) Error.captureStackTrace(err, assert)
    throw err
  }
}

},{}],52:[function(require,module,exports){
const sodium = require('sodium-universal')
const b4a = require('b4a')

module.exports = class CipherState {
  constructor (key) {
    this.key = key || null
    this.nonce = 0
    this.CIPHER_ALG = 'ChaChaPoly'
  }

  initialiseKey (key) {
    this.key = key
    this.nonce = 0
  }

  setNonce (nonce) {
    this.nonce = nonce
  }

  encrypt (plaintext, ad) {
    if (!this.hasKey) return plaintext
    if (!ad) ad = b4a.alloc(0)

    const ciphertext = encryptWithAD(this.key, this.nonce, ad, plaintext)
    this.nonce++

    return ciphertext
  }

  decrypt (ciphertext, ad) {
    if (!this.hasKey) return ciphertext
    if (!ad) ad = b4a.alloc(0)

    const plaintext = decryptWithAD(this.key, this.nonce, ad, ciphertext)
    this.nonce++

    return plaintext
  }

  get hasKey () {
    return this.key !== null
  }

  _clear () {
    sodium.sodium_memzero(this.key)
    this.key = null
    this.nonce = null
  }

  static get MACBYTES () {
    return 16
  }

  static get NONCEBYTES () {
    return 8
  }

  static get KEYBYTES () {
    return 32
  }
}

function encryptWithAD (key, counter, additionalData, plaintext) {
  // for our purposes, additionalData will always be a pubkey so we encode from hex
  if (!b4a.isBuffer(additionalData)) additionalData = b4a.from(additionalData, 'hex')
  if (!b4a.isBuffer(plaintext)) plaintext = b4a.from(plaintext, 'hex')

  const nonce = b4a.alloc(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength)
  view.setUint32(4, counter, true)

  const ciphertext = b4a.alloc(plaintext.byteLength + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)

  sodium.crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, plaintext, additionalData, null, nonce, key)
  return ciphertext
}

function decryptWithAD (key, counter, additionalData, ciphertext) {
  // for our purposes, additionalData will always be a pubkey so we encode from hex
  if (!b4a.isBuffer(additionalData)) additionalData = b4a.from(additionalData, 'hex')
  if (!b4a.isBuffer(ciphertext)) ciphertext = b4a.from(ciphertext, 'hex')

  const nonce = b4a.alloc(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength)
  view.setUint32(4, counter, true)

  const plaintext = b4a.alloc(ciphertext.byteLength - sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)

  sodium.crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, null, ciphertext, additionalData, nonce, key)
  return plaintext
}

},{"b4a":4,"sodium-universal":122}],53:[function(require,module,exports){
/* eslint-disable camelcase */
const {
  crypto_kx_SEEDBYTES,
  crypto_kx_keypair,
  crypto_kx_seed_keypair,
  crypto_scalarmult_BYTES,
  crypto_scalarmult_SCALARBYTES,
  crypto_scalarmult,
  crypto_scalarmult_base
} = require('sodium-universal')

const assert = require('nanoassert')
const b4a = require('b4a')

const DHLEN = crypto_scalarmult_BYTES
const PKLEN = crypto_scalarmult_BYTES
const SKLEN = crypto_scalarmult_SCALARBYTES
const SEEDLEN = crypto_kx_SEEDBYTES
const ALG = '25519'

module.exports = {
  DHLEN,
  PKLEN,
  SKLEN,
  SEEDLEN,
  ALG,
  generateKeyPair,
  generateSeedKeyPair,
  dh
}

function generateKeyPair (privKey) {
  const keyPair = {}

  keyPair.secretKey = privKey || b4a.alloc(SKLEN)
  keyPair.publicKey = b4a.alloc(PKLEN)

  if (privKey) {
    crypto_scalarmult_base(keyPair.publicKey, keyPair.secretKey)
  } else {
    crypto_kx_keypair(keyPair.publicKey, keyPair.secretKey)
  }

  return keyPair
}

function generateSeedKeyPair (seed) {
  assert(seed.byteLength === SKLEN)

  const keyPair = {}
  keyPair.secretKey = b4a.alloc(SKLEN)
  keyPair.publicKey = b4a.alloc(PKLEN)

  crypto_kx_seed_keypair(keyPair.publicKey, keyPair.secretKey, seed)
  return keyPair
}

function dh (publicKey, { secretKey }) {
  assert(secretKey.byteLength === SKLEN)
  assert(publicKey.byteLength === PKLEN)

  const output = b4a.alloc(DHLEN)

  crypto_scalarmult(
    output,
    secretKey,
    publicKey
  )

  return output
}

},{"b4a":4,"nanoassert":51,"sodium-universal":122}],54:[function(require,module,exports){
const hmacBlake2b = require('./hmac')
const assert = require('nanoassert')
const b4a = require('b4a')

const HASHLEN = 64

module.exports = {
  hkdf,
  HASHLEN
}

function hkdf (salt, inputKeyMaterial, info = '', length = 2 * HASHLEN) {
  const pseudoRandomKey = hkdfExtract(salt, inputKeyMaterial)
  const result = hkdfExpand(pseudoRandomKey, info, length)

  const [k1, k2] = [result.slice(0, HASHLEN), result.slice(HASHLEN)]

  return [k1, k2]

  function hkdfExtract (salt, inputKeyMaterial) {
    return hmacDigest(salt, inputKeyMaterial)
  }

  function hkdfExpand (key, info, length) {
    const T = [b4a.from(info)]
    const lengthRatio = length / HASHLEN

    for (let i = 0; i < lengthRatio; i++) {
      const infoBuf = b4a.from(info)
      const toHash = b4a.concat([T[i], infoBuf, b4a.from([i + 1])])

      T[i + 1] = hmacDigest(key, toHash)
    }

    const result = b4a.concat(T.slice(1))
    assert(result.byteLength === length, 'key expansion failed, length not as expected')

    return result
  }
}

function hmacDigest (key, input) {
  const hmac = b4a.alloc(HASHLEN)
  hmacBlake2b(hmac, input, key)

  return hmac
}

},{"./hmac":55,"b4a":4,"nanoassert":51}],55:[function(require,module,exports){
/* eslint-disable camelcase */
const b4a = require('b4a')
const { sodium_memzero, crypto_generichash, crypto_generichash_batch } = require('sodium-universal')

const HASHLEN = 64
const BLOCKLEN = 128
const scratch = b4a.alloc(BLOCKLEN * 3)
const HMACKey = scratch.subarray(BLOCKLEN * 0, BLOCKLEN * 1)
const OuterKeyPad = scratch.subarray(BLOCKLEN * 1, BLOCKLEN * 2)
const InnerKeyPad = scratch.subarray(BLOCKLEN * 2, BLOCKLEN * 3)

// Post-fill is done in the cases where someone caught an exception that
// happened before we were able to clear data at the end

module.exports = function hmac (out, data, key) {
  if (key.byteLength > BLOCKLEN) {
    crypto_generichash(HMACKey.subarray(0, HASHLEN), key)
    sodium_memzero(HMACKey.subarray(HASHLEN))
  } else {
    // Covers key <= BLOCKLEN
    HMACKey.set(key)
    sodium_memzero(HMACKey.subarray(key.byteLength))
  }

  for (let i = 0; i < HMACKey.byteLength; i++) {
    OuterKeyPad[i] = 0x5c ^ HMACKey[i]
    InnerKeyPad[i] = 0x36 ^ HMACKey[i]
  }
  sodium_memzero(HMACKey)

  crypto_generichash_batch(out, [InnerKeyPad].concat(data))
  sodium_memzero(InnerKeyPad)
  crypto_generichash_batch(out, [OuterKeyPad].concat(out))
  sodium_memzero(OuterKeyPad)
}

module.exports.BYTES = HASHLEN
module.exports.KEYBYTES = BLOCKLEN

},{"b4a":4,"sodium-universal":122}],56:[function(require,module,exports){
const assert = require('nanoassert')
const b4a = require('b4a')

const SymmetricState = require('./symmetric-state')
const { HASHLEN } = require('./hkdf')

const PRESHARE_IS = Symbol('initiator static key preshared')
const PRESHARE_RS = Symbol('responder static key preshared')

const TOK_S = Symbol('s')
const TOK_E = Symbol('e')

const TOK_ES = Symbol('es')
const TOK_SE = Symbol('se')
const TOK_EE = Symbol('ee')
const TOK_SS = Symbol('ss')

const HANDSHAKES = Object.freeze({
  XX: [
    [TOK_E],
    [TOK_E, TOK_EE, TOK_S, TOK_ES],
    [TOK_S, TOK_SE]
  ],
  IK: [
    PRESHARE_RS,
    [TOK_E, TOK_ES, TOK_S, TOK_SS],
    [TOK_E, TOK_EE, TOK_SE]
  ]
})

class Writer {
  constructor () {
    this.size = 0
    this.buffers = []
  }

  push (b) {
    this.size += b.byteLength
    this.buffers.push(b)
  }

  end () {
    const all = b4a.alloc(this.size)
    let offset = 0
    for (const b of this.buffers) {
      all.set(b, offset)
      offset += b.byteLength
    }
    return all
  }
}

class Reader {
  constructor (buf) {
    this.offset = 0
    this.buffer = buf
  }

  shift (n) {
    const start = this.offset
    const end = this.offset += n
    if (end > this.buffer.byteLength) throw new Error('Insufficient bytes')
    return this.buffer.subarray(start, end)
  }

  end () {
    return this.shift(this.buffer.byteLength - this.offset)
  }
}

module.exports = class NoiseState extends SymmetricState {
  constructor (pattern, initiator, staticKeypair, opts = {}) {
    super(opts)

    this.s = staticKeypair || this.curve.generateKeyPair()
    this.e = null

    this.re = null
    this.rs = null

    this.pattern = pattern
    this.handshake = HANDSHAKES[this.pattern].slice()

    this.protocol = b4a.from([
      'Noise',
      this.pattern,
      this.DH_ALG,
      this.CIPHER_ALG,
      'BLAKE2b'
    ].join('_'))

    this.initiator = initiator
    this.complete = false

    this.rx = null
    this.tx = null
    this.hash = null
  }

  initialise (prologue, remoteStatic) {
    if (this.protocol.byteLength <= HASHLEN) this.digest.set(this.protocol)
    else this.mixHash(this.protocol)

    this.chainingKey = b4a.from(this.digest)

    this.mixHash(prologue)

    while (!Array.isArray(this.handshake[0])) {
      const message = this.handshake.shift()

      // handshake steps should be as arrays, only
      // preshare tokens are provided otherwise
      assert(message === PRESHARE_RS || message === PRESHARE_IS,
        'Unexpected pattern')

      const takeRemoteKey = this.initiator
        ? message === PRESHARE_RS
        : message === PRESHARE_IS

      if (takeRemoteKey) this.rs = remoteStatic

      const key = takeRemoteKey ? this.rs : this.s.publicKey
      assert(key != null, 'Remote pubkey required')

      this.mixHash(key)
    }
  }

  final () {
    const [k1, k2] = this.split()

    this.tx = this.initiator ? k1 : k2
    this.rx = this.initiator ? k2 : k1

    this.complete = true
    this.hash = this.getHandshakeHash()

    this._clear()
  }

  recv (buf) {
    const r = new Reader(buf)

    for (const pattern of this.handshake.shift()) {
      switch (pattern) {
        case TOK_E :
          this.re = r.shift(this.curve.PKLEN)
          this.mixHash(this.re)
          break

        case TOK_S : {
          const klen = this.hasKey ? this.curve.PKLEN + 16 : this.curve.PKLEN
          this.rs = this.decryptAndHash(r.shift(klen))
          break
        }

        case TOK_EE :
        case TOK_ES :
        case TOK_SE :
        case TOK_SS : {
          const useStatic = keyPattern(pattern, this.initiator)

          const localKey = useStatic.local ? this.s : this.e
          const remoteKey = useStatic.remote ? this.rs : this.re

          this.mixKey(remoteKey, localKey)
          break
        }

        default :
          throw new Error('Unexpected message')
      }
    }

    const payload = this.decryptAndHash(r.end())

    if (!this.handshake.length) this.final()
    return payload
  }

  send (payload = b4a.alloc(0)) {
    const w = new Writer()

    for (const pattern of this.handshake.shift()) {
      switch (pattern) {
        case TOK_E :
          if (this.e === null) this.e = this.curve.generateKeyPair()
          this.mixHash(this.e.publicKey)
          w.push(this.e.publicKey)
          break

        case TOK_S :
          w.push(this.encryptAndHash(this.s.publicKey))
          break

        case TOK_ES :
        case TOK_SE :
        case TOK_EE :
        case TOK_SS : {
          const useStatic = keyPattern(pattern, this.initiator)

          const localKey = useStatic.local ? this.s : this.e
          const remoteKey = useStatic.remote ? this.rs : this.re

          this.mixKey(remoteKey, localKey)
          break
        }

        default :
          throw new Error('Unexpected message')
      }
    }

    w.push(this.encryptAndHash(payload))
    const response = w.end()

    if (!this.handshake.length) this.final()
    return response
  }

  _clear () {
    super._clear()

    this.e.secretKey.fill(0)
    this.e.publicKey.fill(0)

    this.re.fill(0)

    this.e = null
    this.re = null
  }
}

function keyPattern (pattern, initiator) {
  const ret = {
    local: false,
    remote: false
  }

  switch (pattern) {
    case TOK_EE:
      return ret

    case TOK_ES:
      ret.local ^= !initiator
      ret.remote ^= initiator
      return ret

    case TOK_SE:
      ret.local ^= initiator
      ret.remote ^= !initiator
      return ret

    case TOK_SS:
      ret.local ^= 1
      ret.remote ^= 1
      return ret
  }
}

},{"./hkdf":54,"./symmetric-state":57,"b4a":4,"nanoassert":51}],57:[function(require,module,exports){
const sodium = require('sodium-universal')
const assert = require('nanoassert')
const b4a = require('b4a')
const CipherState = require('./cipher')
const curve = require('./dh')
const { HASHLEN, hkdf } = require('./hkdf')

module.exports = class SymmetricState extends CipherState {
  constructor (opts = {}) {
    super()

    this.curve = opts.curve || curve
    this.digest = b4a.alloc(HASHLEN)
    this.chainingKey = null
    this.offset = 0

    this.DH_ALG = this.curve.ALG
  }

  mixHash (data) {
    accumulateDigest(this.digest, data)
  }

  mixKey (remoteKey, localKey) {
    const dh = this.curve.dh(remoteKey, localKey)
    const hkdfResult = hkdf(this.chainingKey, dh)
    this.chainingKey = hkdfResult[0]
    this.initialiseKey(hkdfResult[1].subarray(0, 32))
  }

  encryptAndHash (plaintext) {
    const ciphertext = this.encrypt(plaintext, this.digest)
    accumulateDigest(this.digest, ciphertext)
    return ciphertext
  }

  decryptAndHash (ciphertext) {
    const plaintext = this.decrypt(ciphertext, this.digest)
    accumulateDigest(this.digest, ciphertext)
    return plaintext
  }

  getHandshakeHash (out) {
    if (!out) return this.getHandshakeHash(b4a.alloc(HASHLEN))
    assert(out.byteLength === HASHLEN, `output must be ${HASHLEN} bytes`)

    out.set(this.digest)
    return out
  }

  split () {
    const res = hkdf(this.chainingKey, b4a.alloc(0))
    return res.map(k => k.subarray(0, 32))
  }

  _clear () {
    super._clear()

    sodium.sodium_memzero(this.digest)
    sodium.sodium_memzero(this.chainingKey)

    this.digest = null
    this.chainingKey = null
    this.offset = null

    this.curve = null
  }

  static get alg () {
    return CipherState.alg + '_BLAKE2b'
  }
}

function accumulateDigest (digest, input) {
  const toHash = b4a.concat([digest, input])
  sodium.crypto_generichash(digest, toHash)
}

},{"./cipher":52,"./dh":53,"./hkdf":54,"b4a":4,"nanoassert":51,"sodium-universal":122}],58:[function(require,module,exports){
const b4a = require('b4a')
const c = require('compact-encoding')
const queueTick = require('queue-tick')
const safetyCatch = require('safety-catch')

const MAX_BUFFERED = 32768
const MAX_BACKLOG = Infinity // TODO: impl "open" backpressure
const MAX_BATCH = 8 * 1024 * 1024

class Channel {
  constructor (mux, info, userData, protocol, aliases, id, handshake, messages, onopen, onclose, ondestroy, ondrain) {
    this.userData = userData
    this.protocol = protocol
    this.aliases = aliases
    this.id = id
    this.handshake = null
    this.messages = []

    this.opened = false
    this.closed = false
    this.destroyed = false

    this.onopen = onopen
    this.onclose = onclose
    this.ondestroy = ondestroy
    this.ondrain = ondrain

    this._handshake = handshake
    this._mux = mux
    this._info = info
    this._localId = 0
    this._remoteId = 0
    this._active = 0
    this._extensions = null

    this._decBound = this._dec.bind(this)
    this._decAndDestroyBound = this._decAndDestroy.bind(this)

    for (const m of messages) this.addMessage(m)
  }

  get drained () {
    return this._mux.drained
  }

  open (handshake) {
    const id = this._mux._free.length > 0
      ? this._mux._free.pop()
      : this._mux._local.push(null) - 1

    this._info.opened++
    this._localId = id + 1
    this._mux._local[id] = this

    if (this._remoteId === 0) {
      this._info.outgoing.push(this._localId)
    }

    const state = { buffer: null, start: 2, end: 2 }

    c.uint.preencode(state, this._localId)
    c.string.preencode(state, this.protocol)
    c.buffer.preencode(state, this.id)
    if (this._handshake) this._handshake.preencode(state, handshake)

    state.buffer = this._mux._alloc(state.end)

    state.buffer[0] = 0
    state.buffer[1] = 1
    c.uint.encode(state, this._localId)
    c.string.encode(state, this.protocol)
    c.buffer.encode(state, this.id)
    if (this._handshake) this._handshake.encode(state, handshake)

    this._mux._write0(state.buffer)
  }

  _dec () {
    if (--this._active === 0 && this.closed === true) this._destroy()
  }

  _decAndDestroy (err) {
    this._dec()
    this._mux._safeDestroy(err)
  }

  _fullyOpenSoon () {
    this._mux._remote[this._remoteId - 1].session = this
    queueTick(this._fullyOpen.bind(this))
  }

  _fullyOpen () {
    if (this.opened === true || this.closed === true) return

    const remote = this._mux._remote[this._remoteId - 1]

    this.opened = true
    this.handshake = this._handshake ? this._handshake.decode(remote.state) : null
    this._track(this.onopen(this.handshake, this))

    remote.session = this
    remote.state = null
    if (remote.pending !== null) this._drain(remote)
  }

  _drain (remote) {
    for (let i = 0; i < remote.pending.length; i++) {
      const p = remote.pending[i]
      this._mux._buffered -= byteSize(p.state)
      this._recv(p.type, p.state)
    }

    remote.pending = null
    this._mux._resumeMaybe()
  }

  _track (p) {
    if (isPromise(p) === true) {
      this._active++
      p.then(this._decBound, this._decAndDestroyBound)
    }
  }

  _close (isRemote) {
    if (this.closed === true) return
    this.closed = true

    this._info.opened--

    if (this._remoteId > 0) {
      this._mux._remote[this._remoteId - 1] = null
      this._remoteId = 0
      // If remote has acked, we can reuse the local id now
      // otherwise, we need to wait for the "ack" to arrive
      this._mux._free.push(this._localId - 1)
    }

    this._mux._local[this._localId - 1] = null
    this._localId = 0

    this._mux._gc(this._info)
    this._track(this.onclose(isRemote, this))

    if (this._active === 0) this._destroy()
  }

  _destroy () {
    if (this.destroyed === true) return
    this.destroyed = true
    this._track(this.ondestroy(this))
  }

  _recv (type, state) {
    if (type < this.messages.length) {
      this.messages[type].recv(state, this)
    }
  }

  cork () {
    this._mux.cork()
  }

  uncork () {
    this._mux.uncork()
  }

  close () {
    if (this.closed === true) return

    const state = { buffer: null, start: 2, end: 2 }

    c.uint.preencode(state, this._localId)

    state.buffer = this._mux._alloc(state.end)

    state.buffer[0] = 0
    state.buffer[1] = 3
    c.uint.encode(state, this._localId)

    this._close(false)
    this._mux._write0(state.buffer)
  }

  addMessage (opts) {
    if (!opts) return this._skipMessage()

    const type = this.messages.length
    const encoding = opts.encoding || c.raw
    const onmessage = opts.onmessage || noop

    const s = this
    const typeLen = encodingLength(c.uint, type)

    const m = {
      type,
      encoding,
      onmessage,
      recv (state, session) {
        session._track(m.onmessage(encoding.decode(state), session))
      },
      send (m, session = s) {
        if (session.closed === true) return false

        const mux = session._mux
        const state = { buffer: null, start: 0, end: typeLen }

        if (mux._batch !== null) {
          encoding.preencode(state, m)
          state.buffer = mux._alloc(state.end)

          c.uint.encode(state, type)
          encoding.encode(state, m)

          mux._pushBatch(session._localId, state.buffer)
          return true
        }

        c.uint.preencode(state, session._localId)
        encoding.preencode(state, m)

        state.buffer = mux._alloc(state.end)

        c.uint.encode(state, session._localId)
        c.uint.encode(state, type)
        encoding.encode(state, m)

        mux.drained = mux.stream.write(state.buffer)

        return mux.drained
      }
    }

    this.messages.push(m)

    return m
  }

  _skipMessage () {
    const type = this.messages.length
    const m = {
      type,
      encoding: c.raw,
      onmessage: noop,
      recv (state, session) {},
      send (m, session) {}
    }

    this.messages.push(m)
    return m
  }
}

module.exports = class Protomux {
  constructor (stream, { alloc } = {}) {
    if (stream.userData === null) stream.userData = this

    this.isProtomux = true
    this.stream = stream
    this.corked = 0
    this.drained = true

    this._alloc = alloc || (typeof stream.alloc === 'function' ? stream.alloc.bind(stream) : b4a.allocUnsafe)
    this._safeDestroyBound = this._safeDestroy.bind(this)

    this._remoteBacklog = 0
    this._buffered = 0
    this._paused = false
    this._remote = []
    this._local = []
    this._free = []
    this._batch = null
    this._batchState = null

    this._infos = new Map()
    this._notify = new Map()

    this.stream.on('data', this._ondata.bind(this))
    this.stream.on('drain', this._ondrain.bind(this))
    this.stream.on('end', this._onend.bind(this))
    this.stream.on('error', noop) // we handle this in "close"
    this.stream.on('close', this._shutdown.bind(this))
  }

  static from (stream, opts) {
    if (stream.userData && stream.userData.isProtomux) return stream.userData
    if (stream.isProtomux) return stream
    return new this(stream, opts)
  }

  static isProtomux (mux) {
    return typeof mux === 'object' && mux.isProtomux === true
  }

  * [Symbol.iterator] () {
    for (const session of this._local) {
      if (session !== null) yield session
    }
  }

  cork () {
    if (++this.corked === 1) {
      this._batch = []
      this._batchState = { buffer: null, start: 0, end: 1 }
    }
  }

  uncork () {
    if (--this.corked === 0) {
      this._sendBatch(this._batch, this._batchState)
      this._batch = null
      this._batchState = null
    }
  }

  pair ({ protocol, id = null }, notify) {
    this._notify.set(toKey(protocol, id), notify)
  }

  unpair ({ protocol, id = null }) {
    this._notify.delete(toKey(protocol, id))
  }

  opened ({ protocol, id = null }) {
    const key = toKey(protocol, id)
    const info = this._infos.get(key)
    return info ? info.opened > 0 : false
  }

  createChannel ({ userData = null, protocol, aliases = [], id = null, unique = true, handshake = null, messages = [], onopen = noop, onclose = noop, ondestroy = noop, ondrain = noop }) {
    if (this.stream.destroyed) return null

    const info = this._get(protocol, id, aliases)
    if (unique && info.opened > 0) return null

    if (info.incoming.length === 0) {
      return new Channel(this, info, userData, protocol, aliases, id, handshake, messages, onopen, onclose, ondestroy, ondrain)
    }

    this._remoteBacklog--

    const remoteId = info.incoming.shift()
    const r = this._remote[remoteId - 1]
    if (r === null) return null

    const session = new Channel(this, info, userData, protocol, aliases, id, handshake, messages, onopen, onclose, ondestroy, ondrain)

    session._remoteId = remoteId
    session._fullyOpenSoon()

    return session
  }

  _pushBatch (localId, buffer) {
    if (this._batchState.end >= MAX_BATCH) {
      this._sendBatch(this._batch, this._batchState)
      this._batch = []
      this._batchState = { buffer: null, start: 0, end: 1 }
    }

    if (this._batch.length === 0 || this._batch[this._batch.length - 1].localId !== localId) {
      this._batchState.end++
      c.uint.preencode(this._batchState, localId)
    }
    c.buffer.preencode(this._batchState, buffer)
    this._batch.push({ localId, buffer })
  }

  _sendBatch (batch, state) {
    if (batch.length === 0) return

    let prev = batch[0].localId

    state.buffer = this._alloc(state.end)
    state.buffer[state.start++] = 0
    state.buffer[state.start++] = 0

    c.uint.encode(state, prev)

    for (let i = 0; i < batch.length; i++) {
      const b = batch[i]
      if (prev !== b.localId) {
        state.buffer[state.start++] = 0
        c.uint.encode(state, (prev = b.localId))
      }
      c.buffer.encode(state, b.buffer)
    }

    this.drained = this.stream.write(state.buffer)
  }

  _get (protocol, id, aliases = []) {
    const key = toKey(protocol, id)

    let info = this._infos.get(key)
    if (info) return info

    info = { key, protocol, aliases: [], id, pairing: 0, opened: 0, incoming: [], outgoing: [] }
    this._infos.set(key, info)

    for (const alias of aliases) {
      const key = toKey(alias, id)
      info.aliases.push(key)

      this._infos.set(key, info)
    }

    return info
  }

  _gc (info) {
    if (info.opened === 0 && info.outgoing.length === 0 && info.incoming.length === 0) {
      this._infos.delete(info.key)

      for (const alias of info.aliases) this._infos.delete(alias)
    }
  }

  _ondata (buffer) {
    if (buffer.byteLength === 0) return // ignore empty frames...
    try {
      const state = { buffer, start: 0, end: buffer.byteLength }
      this._decode(c.uint.decode(state), state)
    } catch (err) {
      this._safeDestroy(err)
    }
  }

  _ondrain () {
    this.drained = true

    for (const s of this._local) {
      if (s !== null) s._track(s.ondrain(s))
    }
  }

  _onend () { // TODO: support half open mode for the users who wants that here
    this.stream.end()
  }

  _decode (remoteId, state) {
    const type = c.uint.decode(state)

    if (remoteId === 0) {
      this._oncontrolsession(type, state)
      return
    }

    const r = remoteId <= this._remote.length ? this._remote[remoteId - 1] : null

    // if the channel is closed ignore - could just be a pipeline message...
    if (r === null) return

    if (r.pending !== null) {
      this._bufferMessage(r, type, state)
      return
    }

    r.session._recv(type, state)
  }

  _oncontrolsession (type, state) {
    switch (type) {
      case 0:
        this._onbatch(state)
        break

      case 1:
        this._onopensession(state)
        break

      case 2:
        this._onrejectsession(state)
        break

      case 3:
        this._onclosesession(state)
        break
    }
  }

  _bufferMessage (r, type, { buffer, start, end }) {
    const state = { buffer, start, end } // copy
    r.pending.push({ type, state })
    this._buffered += byteSize(state)
    this._pauseMaybe()
  }

  _pauseMaybe () {
    if (this._paused === true || this._buffered <= MAX_BUFFERED) return
    this._paused = true
    this.stream.pause()
  }

  _resumeMaybe () {
    if (this._paused === false || this._buffered > MAX_BUFFERED) return
    this._paused = false
    this.stream.resume()
  }

  _onbatch (state) {
    const end = state.end
    let remoteId = c.uint.decode(state)

    while (state.end > state.start) {
      const len = c.uint.decode(state)
      if (len === 0) {
        remoteId = c.uint.decode(state)
        continue
      }
      state.end = state.start + len
      this._decode(remoteId, state)
      state.start = state.end
      state.end = end
    }
  }

  _onopensession (state) {
    const remoteId = c.uint.decode(state)
    const protocol = c.string.decode(state)
    const id = c.buffer.decode(state)

    // remote tried to open the control session - auto reject for now
    // as we can use as an explicit control protocol declaration if we need to
    if (remoteId === 0) {
      this._rejectSession(0)
      return
    }

    const rid = remoteId - 1
    const info = this._get(protocol, id)

    // allow the remote to grow the ids by one
    if (this._remote.length === rid) {
      this._remote.push(null)
    }

    if (rid >= this._remote.length || this._remote[rid] !== null) {
      throw new Error('Invalid open message')
    }

    if (info.outgoing.length > 0) {
      const localId = info.outgoing.shift()
      const session = this._local[localId - 1]

      if (session === null) { // we already closed the channel - ignore
        this._free.push(localId - 1)
        return
      }

      this._remote[rid] = { state, pending: null, session: null }

      session._remoteId = remoteId
      session._fullyOpen()
      return
    }

    const copyState = { buffer: state.buffer, start: state.start, end: state.end }
    this._remote[rid] = { state: copyState, pending: [], session: null }

    if (++this._remoteBacklog > MAX_BACKLOG) {
      throw new Error('Remote exceeded backlog')
    }

    info.pairing++
    info.incoming.push(remoteId)

    this._requestSession(protocol, id, info).catch(this._safeDestroyBound)
  }

  _onrejectsession (state) {
    const localId = c.uint.decode(state)

    // TODO: can be done smarter...
    for (const info of this._infos.values()) {
      const i = info.outgoing.indexOf(localId)
      if (i === -1) continue

      info.outgoing.splice(i, 1)

      const session = this._local[localId - 1]

      this._free.push(localId - 1)
      if (session !== null) session._close(true)

      this._gc(info)
      return
    }

    throw new Error('Invalid reject message')
  }

  _onclosesession (state) {
    const remoteId = c.uint.decode(state)

    if (remoteId === 0) return // ignore

    const rid = remoteId - 1
    const r = rid < this._remote.length ? this._remote[rid] : null

    if (r === null) return

    if (r.session !== null) r.session._close(true)
  }

  async _requestSession (protocol, id, info) {
    const notify = this._notify.get(toKey(protocol, id)) || this._notify.get(toKey(protocol, null))

    if (notify) await notify(id)

    if (--info.pairing > 0) return

    while (info.incoming.length > 0) {
      this._rejectSession(info, info.incoming.shift())
    }

    this._gc(info)
  }

  _rejectSession (info, remoteId) {
    if (remoteId > 0) {
      const r = this._remote[remoteId - 1]

      if (r.pending !== null) {
        for (let i = 0; i < r.pending.length; i++) {
          this._buffered -= byteSize(r.pending[i].state)
        }
      }

      this._remote[remoteId - 1] = null
      this._resumeMaybe()
    }

    const state = { buffer: null, start: 2, end: 2 }

    c.uint.preencode(state, remoteId)

    state.buffer = this._alloc(state.end)

    state.buffer[0] = 0
    state.buffer[1] = 2
    c.uint.encode(state, remoteId)

    this._write0(state.buffer)
  }

  _write0 (buffer) {
    if (this._batch !== null) {
      this._pushBatch(0, buffer.subarray(1))
      return
    }

    this.drained = this.stream.write(buffer)
  }

  destroy (err) {
    this.stream.destroy(err)
  }

  _safeDestroy (err) {
    safetyCatch(err)
    this.stream.destroy(err)
  }

  _shutdown () {
    for (const s of this._local) {
      if (s !== null) s._close(true)
    }
  }
}

function noop () {}

function toKey (protocol, id) {
  return protocol + '##' + (id ? b4a.toString(id, 'hex') : '')
}

function byteSize (state) {
  return 512 + (state.end - state.start)
}

function isPromise (p) {
  return !!(p && typeof p.then === 'function')
}

function encodingLength (enc, val) {
  const state = { buffer: null, start: 0, end: 0 }
  enc.preencode(state, val)
  return state.end
}

},{"b4a":4,"compact-encoding":16,"queue-tick":59,"safety-catch":65}],59:[function(require,module,exports){
module.exports = typeof queueMicrotask === 'function' ? queueMicrotask : (fn) => Promise.resolve().then(fn)

},{}],60:[function(require,module,exports){
const simdle = require('simdle-universal')

const INDEX_LEN = (16 /* root */ + 128 * 16 /* children */) * 2

const get = exports.get = function get (field, bit) {
  const n = field.byteLength * 8

  if (bit < 0) bit += n
  if (bit < 0 || bit >= n) return false

  const m = field.BYTES_PER_ELEMENT * 8

  const offset = bit & (m - 1)
  const i = (bit - offset) / m

  return (field[i] & (1 << offset)) !== 0
}

const set = exports.set = function set (field, bit, value = true) {
  const n = field.byteLength * 8

  if (bit < 0) bit += n
  if (bit < 0 || bit >= n) return false

  const m = field.BYTES_PER_ELEMENT * 8

  const offset = bit & (m - 1)
  const i = (bit - offset) / m
  const mask = 1 << offset

  if (value) {
    if ((field[i] & mask) !== 0) return false
  } else {
    if ((field[i] & mask) === 0) return false
  }

  field[i] ^= mask

  return true
}

exports.fill = function fill (field, value, start = 0, end = field.byteLength * 8) {
  const n = field.byteLength * 8

  if (start < 0) start += n
  if (end < 0) end += n
  if (start < 0 || start >= field.byteLength * 8 || start >= end) return field

  const m = field.BYTES_PER_ELEMENT * 8

  let i, j

  {
    const offset = start & (m - 1)
    i = (start - offset) / m

    if (offset !== 0) {
      let shift = m - offset
      if (end - start < shift) shift = end - start

      const mask = ((1 << shift) - 1) << offset

      if (value) field[i] |= mask
      else field[i] &= ~mask

      i++
    }
  }

  {
    const offset = end & (m - 1)
    j = (end - offset) / m

    if (offset !== 0 && j >= i) {
      const mask = (1 << offset) - 1

      if (value) field[j] |= mask
      else field[j] &= ~mask
    }
  }

  if (i < j) field.fill(value ? (2 ** m) - 1 : 0, i, j)

  return field
}

exports.clear = function clear (field, ...chunks) {
  const n = field.byteLength

  for (const chunk of chunks) {
    if (chunk.offset >= n) continue

    const m = chunk.field.byteLength

    let i = chunk.offset
    let j = 0

    while (((i & 15) !== 0 || (j & 15) !== 0) && i < n && j < m) {
      field[i] = field[i] & ~chunk.field[j]
      i++
      j++
    }

    if (i + 15 < n && j + 15 < m) {
      const len = Math.min(n - (n & 15) - i, m - (m & 15) - j)

      simdle.clear(field.subarray(i, i + len), chunk.field.subarray(j, j + len), field.subarray(i, i + len))
    }

    while (i < n && j < m) {
      field[i] = field[i] & ~chunk.field[j]
      i++
      j++
    }
  }
}

function bitOffset (bit, offset) {
  return !bit ? offset : (INDEX_LEN * 8 / 2) + offset
}

function byteOffset (bit, offset) {
  return !bit ? offset : (INDEX_LEN / 2) + offset
}

exports.findFirst = function findFirst (field, value, position = 0) {
  const n = field.byteLength * 8

  if (position < 0) position += n
  if (position < 0) position = 0
  if (position >= n) return -1

  value = !!value

  for (let i = position; i < n; i++) {
    if (get(field, i) === value) return i
  }

  return -1
}

exports.findLast = function findLast (field, value, position = field.byteLength * 8 - 1) {
  const n = field.byteLength * 8

  if (position < 0) position += n
  if (position < 0) return -1
  if (position >= n) position = n - 1

  value = !!value

  for (let i = position; i >= 0; i--) {
    if (get(field, i) === value) return i
  }

  return -1
}

const Index = exports.Index = class Index {
  static from (fieldOrChunks, byteLength = -1) {
    if (Array.isArray(fieldOrChunks)) {
      return new SparseIndex(fieldOrChunks, byteLength)
    } else {
      return new DenseIndex(fieldOrChunks, byteLength)
    }
  }

  constructor (byteLength) {
    this._byteLength = byteLength
    this.handle = new Uint32Array(INDEX_LEN / 4)
  }

  get byteLength () {
    return this._byteLength
  }

  skipFirst (value, position = 0) {
    const n = this.byteLength * 8

    if (position < 0) position += n
    if (position < 0) position = 0
    if (position >= n) return n - 1

    let i = Math.floor(position / 16384)

    if (i > 127) return position

    while (i <= 127 && get(this.handle, bitOffset(value, i))) {
      i++
    }

    if (i === 128) return n - 1

    let k = i * 16384
    let j = 0

    if (position > k) j = Math.floor((position - k) / 128)

    while (j <= 127 && get(this.handle, bitOffset(value, i * 128 + j + 128))) {
      j++
      k += 128
    }

    if (j === 128 && i !== 127) return this.skipFirst(value, (i + 1) * 16384)

    if (k > position) position = k

    return position < n ? position : n - 1
  }

  skipLast (value, position = this.byteLength * 8 - 1) {
    const n = this.byteLength * 8

    if (position < 0) position += n
    if (position < 0) return 0
    if (position >= n) position = n - 1

    let i = Math.floor(position / 16384)

    if (i > 127) return position

    while (i >= 0 && get(this.handle, bitOffset(value, i))) {
      i--
    }

    if (i === -1) return 0

    let k = ((i + 1) * 16384) - 1
    let j = 127

    if (position < k) j = 128 - Math.ceil((k - position) / 128)

    while (j >= 0 && get(this.handle, bitOffset(value, i * 128 + j + 128))) {
      j--
      k -= 128
    }

    if (j === -1 && i !== 0) return this.skipLast(value, i * 16384 - 1)

    if (k < position) position = k

    return position
  }
}

class DenseIndex extends Index {
  constructor (field, byteLength) {
    super(byteLength)
    this.field = field

    const m = field.BYTES_PER_ELEMENT

    for (let i = 0; i < 128; i++) {
      for (let j = 0; j < 128; j++) {
        const offset = (i * 128 + j) * 16
        let allz = true
        let allo = false

        if (offset + 16 <= this.field.byteLength) {
          const vec = this.field.subarray(offset / m, (offset + 16) / m)

          allz = simdle.allz(vec)
          allo = simdle.allo(vec)
        }

        const k = i * 128 + 128 + j

        set(this.handle, bitOffset(false, k), allz)
        set(this.handle, bitOffset(true, k), allo)
      }

      {
        const offset = byteOffset(false, i * 16 + 16) / 4
        const allo = simdle.allo(this.handle.subarray(offset, offset + 4))

        set(this.handle, bitOffset(false, i), allo)
      }

      {
        const offset = byteOffset(true, i * 16 + 16) / 4
        const allo = simdle.allo(this.handle.subarray(offset, offset + 4))

        set(this.handle, bitOffset(true, i), allo)
      }
    }
  }

  get byteLength () {
    if (this._byteLength !== -1) return this._byteLength
    return this.field.byteLength
  }

  update (bit) {
    const n = this.byteLength * 8

    if (bit < 0) bit += n
    if (bit < 0 || bit >= n) return false

    const m = this.field.BYTES_PER_ELEMENT

    const i = Math.floor(bit / 16384)
    const j = Math.floor(bit / 128)

    const offset = (j * 16) / m
    const vec = this.field.subarray(offset, offset + (16 / m))

    const allz = simdle.allz(vec)
    const allo = simdle.allo(vec)

    let changed = false

    if (set(this.handle, bitOffset(false, 128 + j), allz)) {
      changed = true

      const offset = byteOffset(false, i * 16 + 16) / 4
      const allo = simdle.allo(this.handle.subarray(offset, offset + 4))

      set(this.handle, bitOffset(false, i), allo)
    }

    if (set(this.handle, bitOffset(true, 128 + j), allo)) {
      changed = true

      const offset = byteOffset(true, i * 16 + 16) / 4
      const allo = simdle.allo(this.handle.subarray(offset, offset + 4))

      set(this.handle, bitOffset(true, i), allo)
    }

    return changed
  }
}

function selectChunk (chunks, offset) {
  for (let i = 0; i < chunks.length; i++) {
    const next = chunks[i]

    const start = next.offset
    const end = next.offset + next.field.byteLength

    if (offset >= start && offset + 16 <= end) {
      return next
    }
  }

  return null
}

class SparseIndex extends Index {
  constructor (chunks, byteLength) {
    super(byteLength)
    this.chunks = chunks

    for (let i = 0; i < 128; i++) {
      for (let j = 0; j < 128; j++) {
        const offset = (i * 128 + j) * 16
        let allz = true
        let allo = false

        const chunk = selectChunk(this.chunks, offset)

        if (chunk !== null) {
          const m = chunk.field.BYTES_PER_ELEMENT

          const vec = chunk.field.subarray((offset - chunk.offset) / m, (offset - chunk.offset + 16) / m)

          allz = simdle.allz(vec)
          allo = simdle.allo(vec)
        }

        const k = i * 128 + 128 + j

        set(this.handle, bitOffset(false, k), allz)
        set(this.handle, bitOffset(true, k), allo)
      }

      {
        const offset = byteOffset(false, i * 16 + 16) / 4
        const allo = simdle.allo(this.handle.subarray(offset, offset + 4))

        set(this.handle, bitOffset(false, i), allo)
      }

      {
        const offset = byteOffset(true, i * 16 + 16) / 4
        const allo = simdle.allo(this.handle.subarray(offset, offset + 4))

        set(this.handle, bitOffset(true, i), allo)
      }
    }
  }

  get byteLength () {
    if (this._byteLength !== -1) return this._byteLength
    const last = this.chunks[this.chunks.length - 1]
    return last ? last.offset + last.field.byteLength : 0
  }

  update (bit) {
    const n = this.byteLength * 8

    if (bit < 0) bit += n
    if (bit < 0 || bit >= n) return false

    const i = Math.floor(bit / 16384)
    const j = Math.floor(bit / 128)

    const offset = j * 16

    const chunk = selectChunk(this.chunks, offset)

    if (chunk === null) return false

    const m = chunk.field.BYTES_PER_ELEMENT

    const vec = chunk.field.subarray((offset - chunk.offset) / m, (offset - chunk.offset + 16) / m)

    const allz = simdle.allz(vec)
    const allo = simdle.allo(vec)

    let changed = false

    if (set(this.handle, bitOffset(false, 128 + j), allz)) {
      changed = true

      const offset = byteOffset(false, i * 16 + 16) / 4
      const allo = simdle.allo(this.handle.subarray(offset, offset + 4))

      set(this.handle, bitOffset(false, i), allo)
    }

    if (set(this.handle, bitOffset(true, 128 + j), allo)) {
      changed = true

      const offset = byteOffset(true, i * 16 + 16) / 4
      const allo = simdle.allo(this.handle.subarray(offset, offset + 4))

      set(this.handle, bitOffset(true, i), allo)
    }

    return changed
  }
}

},{"simdle-universal":74}],61:[function(require,module,exports){
module.exports = function () {
  throw new Error('random-access-file is not supported in the browser')
}

},{}],62:[function(require,module,exports){
module.exports = class RandomArrayIterator {
  constructor (values) {
    this.values = values
    this.start = 0
    this.length = this.values.length
  }

  next () {
    if (this.length === 0) {
      if (this.start === 0) return { done: true, value: undefined }
      this.length = this.start
      this.start = 0
    }

    const i = this.start + ((Math.random() * this.length) | 0)
    const j = this.start + --this.length
    const value = this.values[i]

    this.values[i] = this.values[j]
    this.values[j] = value

    return { done: false, value }
  }

  dequeue () {
    this.values[this.start + this.length] = this.values[this.values.length - 1]
    this.values.pop()
  }

  requeue () {
    const i = this.start + this.length
    const value = this.values[i]
    this.values[i] = this.values[this.start]
    this.values[this.start++] = value
  }

  restart () {
    this.start = 0
    this.length = this.values.length
    return this
  }

  [Symbol.iterator] () {
    return this
  }
}

},{}],63:[function(require,module,exports){
class WriteLock {
  constructor (parent) {
    this.writing = false

    this._waiting = []
    this._parent = parent
    this._wait = pushToQueue.bind(this, this._waiting)
  }

  get locked () {
    return this.writing || this._parent.read.readers > 0
  }

  get waiting () {
    return this._waiting.length
  }

  lock () {
    if (this._parent._destroying) {
      return Promise.reject(this._parent._destroyError)
    }

    if (this.writing === false && this._parent.read.readers === 0) {
      this.writing = true
      return Promise.resolve()
    }

    return new Promise(this._wait)
  }

  unlock () {
    this.writing = false
    this._parent._bump()
  }

  async flush () {
    if (this.writing === false) return
    try {
      await this.lock()
    } catch {
      return
    }
    this.unlock()
  }
}

class ReadLock {
  constructor (parent) {
    this.readers = 0

    this._waiting = []
    this._parent = parent
    this._wait = pushToQueue.bind(this, this._waiting)
  }

  get locked () {
    return this._parent.writing
  }

  get waiting () {
    return this._waiting.length
  }

  lock () {
    if (this._parent._destroying) {
      return Promise.reject(this._parent._destroyError)
    }

    if (this._parent.write.writing === false) {
      this.readers++
      return Promise.resolve()
    }

    return new Promise(this._wait)
  }

  unlock () {
    this.readers--
    this._parent._bump()
  }

  async flush () {
    if (this.writing === false) return
    try {
      await this.lock()
    } catch {
      return
    }
    this.unlock()
  }
}

module.exports = class ReadWriteLock {
  constructor () {
    this.read = new ReadLock(this)
    this.write = new WriteLock(this)

    this._destroyError = null
    this._destroying = null
  }

  get destroyed () {
    return !!this._destroying
  }

  destroy (err) {
    if (this._destroying) return this._destroying

    this._destroying = Promise.all([this.read.flush(), this.write.flush()])
    this._destroyError = err || new Error('Mutex has been destroyed')

    if (err) {
      while (this.read._waiting) this._waiting.shift()[1](err)
      while (this.write._waiting) this._waiting.shift()[1](err)
    }

    return this._destroying
  }

  _bump () {
    if (this.write.writing === false && this.read.readers === 0 && this.write._waiting.length > 0) {
      this.write.writing = true
      this.write._waiting.shift()[0]()
    }
    while (this.write.writing === false && this.read._waiting.length > 0) {
      this.read.readers++
      this.read._waiting.shift()[0]()
    }
  }
}

function pushToQueue (queue, resolve, reject) {
  queue.push([resolve, reject])
}

},{}],64:[function(require,module,exports){
const EventEmitter = require('events')

module.exports = class ReadyResource extends EventEmitter {
  constructor () {
    super()

    this.opening = null
    this.closing = null

    this.opened = false
    this.closed = false
  }

  ready () {
    if (this.opening) return this.opening
    this.opening = open(this)
    return this.opening
  }

  close () {
    if (this.closing) return this.closing
    this.closing = close(this)
    return this.closing
  }

  async _open () {
    // add impl here
  }

  async _close () {
    // add impl here
  }
}

async function open (self) {
  await self._open()
  self.opened = true
  self.emit('ready')
}

async function close (self) {
  if (self.opened === false && self.opening !== null) await self.opening
  await self._close()
  self.closed = true
  self.emit('close')
}

},{"events":22}],65:[function(require,module,exports){
module.exports = safetyCatch

function isActuallyUncaught (err) {
  if (!err) return false
  return err instanceof TypeError ||
    err instanceof SyntaxError ||
    err instanceof ReferenceError ||
    err instanceof EvalError ||
    err instanceof RangeError ||
    err instanceof URIError ||
    err.code === 'ERR_ASSERTION'
}

function throwErrorNT (err) {
  queueMicrotask(() => { throw err })
}

function safetyCatch (err) {
  if (isActuallyUncaught(err)) {
    throwErrorNT(err)
    throw err
  }
}

},{}],66:[function(require,module,exports){
const js = require('./sha256.js')
const wasm = require('sha256-wasm')

var Proto = js

module.exports = function () {
  return new Proto()
}

module.exports.ready = function (cb) {
  wasm.ready(function () { // ignore errors
    cb()
  })
}

module.exports.WASM_SUPPORTED = wasm.WASM_SUPPORTED
module.exports.WASM_LOADED = false

var SHA256_BYTES = module.exports.SHA256_BYTES = 32

wasm.ready(function (err) {
  if (!err) {
    module.exports.WASM_LOADED = true
    module.exports = Proto = wasm
  }
})

},{"./sha256.js":67,"sha256-wasm":68}],67:[function(require,module,exports){
const assert = require('nanoassert')
const b4a = require('b4a')

module.exports = Sha256
const SHA256_BYTES = module.exports.SHA256_BYTES = 32
const BLOCKSIZE = 64

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

function expand (a, b, c, d) {
  var b_ = (((a >>> 17) | (a << 15)) ^ ((a >>> 19) | (a << 13)) ^ (a >>> 10)) + b
  var d_ = (((c >>> 7) | (c << 25)) ^ ((c >>> 18) | (c << 14)) ^ (c >>> 3)) + d

  return (b_ + d_) << 0
}

function compress (state, words) {
  // initialise registers
  var ch, maj, s0, s1, T1, T2
  var [a, b, c, d, e, f, g, h] = state

  // expand message schedule
  const w = new Uint32Array(64)
  for (let i = 0; i < 16; i++) w[i] = bswap(words[i])
  for (let i = 16; i < 64; i++) w[i] = expand(w[i - 2], w[i - 7], w[i - 15], w[i - 16])
  for (let i = 0; i < 64; i += 4) round(i)

  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h

  function round (n) {
    ch = (e & f) ^ (~e & g)
    maj = (a & b) ^ (a & c) ^ (b & c)
    s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))
    s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))
    T1 = h + ch + s1 + w[n] + K[n]
    T2 = s0 + maj
    h = d + T1
    d = T1 + T2

    ch = (h & e) ^ (~h & f)
    maj = (d & a) ^ (d & b) ^ (a & b)
    s0 = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10))
    s1 = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7))
    T1 = g + ch + s1 + w[n + 1] + K[n + 1]
    T2 = s0 + maj
    g = c + T1
    c = T1 + T2

    ch = (g & h) ^ (~g & e)
    maj = (c & d) ^ (c & a) ^ (d & a)
    s0 = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10))
    s1 = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7))
    T1 = f + ch + s1 + w[n + 2] + K[n + 2]
    T2 = s0 + maj
    f = b + T1
    b = T1 + T2

    ch = (f & g) ^ (~f & h)
    maj = (b & c) ^ (b & d) ^ (c & d)
    s0 = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10))
    s1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7))
    T1 = e + ch + s1 + w[n + 3] + K[n + 3]
    T2 = s0 + maj
    e = a + T1
    a = T1 + T2
  }
}

function Sha256 () {
  if (!(this instanceof Sha256)) return new Sha256()

  this.buffer = new ArrayBuffer(64)
  this.bytesRead = 0
  this.pos = 0
  this.digestLength = SHA256_BYTES
  this.finalised = false

  this.load = new Uint8Array(this.buffer)
  this.words = new Uint32Array(this.buffer)

  this.state = new Uint32Array([
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
  ])

  return this
}

Sha256.prototype.update = function (input, enc) {
  assert(this.finalised === false, 'Hash instance finalised')

  var [inputBuf, len] = formatInput(input, enc)
  var i = 0
  this.bytesRead += len

  while (len > 0) {
    this.load.set(inputBuf.subarray(i, i + BLOCKSIZE - this.pos), this.pos)
    i += BLOCKSIZE - this.pos
    len -= BLOCKSIZE - this.pos

    if (len < 0) break

    this.pos = 0
    compress(this.state, this.words)
  }

  this.pos = this.bytesRead & 0x3f
  this.load.fill(0, this.pos)

  return this
}

Sha256.prototype.digest = function (enc, offset = 0) {
  assert(this.finalised === false, 'Hash instance finalised')
  this.finalised = true

  this.load.fill(0, this.pos)
  this.load[this.pos] = 0x80

  if (this.pos > 55) {
    compress(this.state, this.words)

    this.words.fill(0)
    this.pos = 0
  }

  const view = new DataView(this.buffer)
  view.setUint32(56, this.bytesRead / 2 ** 29)
  view.setUint32(60, this.bytesRead << 3)

  compress(this.state, this.words)

  const resultBuf = new Uint8Array(this.state.map(bswap).buffer)

  if (!enc) {
    return new Uint8Array(resultBuf)
  }

  if (typeof enc === 'string') {
    return b4a.toString(resultBuf, enc)
  }

  assert(enc instanceof Uint8Array, 'input must be Uint8Array or Buffer')
  assert(enc.byteLength >= this.digestLength + offset, 'input not large enough for digest')

  for (let i = 0; i < this.digestLength; i++) {
    enc[i + offset] = resultBuf[i]
  }

  return enc
}

function HMAC (key) {
  if (!(this instanceof HMAC)) return new HMAC(key)

  this.pad = b4a.alloc(64)
  this.inner = Sha256()
  this.outer = Sha256()

  const keyhash = b4a.alloc(32)
  if (key.byteLength > 64) {
    Sha256().update(key).digest(keyhash)
    key = keyhash
  }

  this.pad.fill(0x36)
  for (let i = 0; i < key.byteLength; i++) {
    this.pad[i] ^= key[i]
  }
  this.inner.update(this.pad)

  this.pad.fill(0x5c)
  for (let i = 0; i < key.byteLength; i++) {
    this.pad[i] ^= key[i]
  }
  this.outer.update(this.pad)

  this.pad.fill(0)
  keyhash.fill(0)
}

HMAC.prototype.update = function (input, enc) {
  this.inner.update(input, enc)
  return this
}

HMAC.prototype.digest = function (enc, offset = 0) {
  this.outer.update(this.inner.digest())
  return this.outer.digest(enc, offset)
}

Sha256.HMAC = HMAC

function formatInput (input, enc) {
  var result = b4a.from(input, enc)

  return [result, result.byteLength]
}

function bswap (a) {
  var r = ((a & 0x00ff00ff) >>> 8) | ((a & 0x00ff00ff) << 24)
  var l = ((a & 0xff00ff00) << 8) | ((a & 0xff00ff00) >>> 24)

  return r | l
}

},{"b4a":4,"nanoassert":51}],68:[function(require,module,exports){
const assert = require('nanoassert')
const b4a = require('b4a')

const wasm = typeof WebAssembly !== 'undefined' && require('./sha256.js')({
  imports: {
    debug: {
      log (...args) {
        console.log(...args.map(int => (int >>> 0).toString(16).padStart(8, '0')))
      },
      log_tee (arg) {
        console.log((arg >>> 0).toString(16).padStart(8, '0'))
        return arg
      }
    }
  }
})

let head = 0
const freeList = []

module.exports = Sha256
const SHA256_BYTES = module.exports.SHA256_BYTES = 32
const INPUT_OFFSET = 40
const STATEBYTES = 108
const BLOCKSIZE = 64

function Sha256 () {
  if (!(this instanceof Sha256)) return new Sha256()
  if (!(wasm)) throw new Error('WASM not loaded. Wait for Sha256.ready(cb)')

  if (!freeList.length) {
    freeList.push(head)
    head += STATEBYTES // need 100 bytes for internal state
  }

  this.finalized = false
  this.digestLength = SHA256_BYTES
  this.pointer = freeList.pop()
  this.pos = 0

  this._memory = new Uint8Array(wasm.memory.buffer)
  this._memory.fill(0, this.pointer, this.pointer + STATEBYTES)

  if (this.pointer + this.digestLength > this._memory.length) this._realloc(this.pointer + STATEBYTES)
}

Sha256.prototype._realloc = function (size) {
  wasm.memory.grow(Math.max(0, Math.ceil(Math.abs(size - this._memory.length) / 65536)))
  this._memory = new Uint8Array(wasm.memory.buffer)
}

Sha256.prototype.update = function (input, enc) {
  assert(this.finalized === false, 'Hash instance finalized')

  if (head % 4 !== 0) head += 4 - head % 4
  assert(head % 4 === 0, 'input shoud be aligned for int32')

  const [inputBuf, length] = formatInput(input, enc)

  assert(inputBuf instanceof Uint8Array, 'input must be Uint8Array or Buffer')

  if (head + length > this._memory.length) this._realloc(head + input.length)

  this._memory.fill(0, head, head + roundUp(length, BLOCKSIZE) - BLOCKSIZE)
  this._memory.set(inputBuf.subarray(0, BLOCKSIZE - this.pos), this.pointer + INPUT_OFFSET + this.pos)
  this._memory.set(inputBuf.subarray(BLOCKSIZE - this.pos), head)

  this.pos = (this.pos + length) & 0x3f
  wasm.sha256(this.pointer, head, length, 0)

  return this
}

Sha256.prototype.digest = function (enc, offset = 0) {
  assert(this.finalized === false, 'Hash instance finalized')

  this.finalized = true
  freeList.push(this.pointer)

  const paddingStart = this.pointer + INPUT_OFFSET + this.pos
  this._memory.fill(0, paddingStart, this.pointer + INPUT_OFFSET + BLOCKSIZE)
  wasm.sha256(this.pointer, head, 0, 1)

  const resultBuf = this._memory.subarray(this.pointer, this.pointer + this.digestLength)

  if (!enc) {
    return resultBuf
  }

  if (typeof enc === 'string') {
    return b4a.toString(resultBuf, enc)
  }

  assert(enc instanceof Uint8Array, 'output must be Uint8Array or Buffer')
  assert(enc.byteLength >= this.digestLength + offset,
    "output must have at least 'SHA256_BYTES' bytes remaining")

  for (let i = 0; i < this.digestLength; i++) {
    enc[i + offset] = resultBuf[i]
  }

  return enc
}

Sha256.WASM = wasm
Sha256.WASM_SUPPORTED = typeof WebAssembly !== 'undefined'

Sha256.ready = function (cb) {
  if (!cb) cb = noop
  if (!wasm) return cb(new Error('WebAssembly not supported'))
  cb()
  return Promise.resolve()
}

Sha256.prototype.ready = Sha256.ready

function HMAC (key) {
  if (!(this instanceof HMAC)) return new HMAC(key)

  this.pad = b4a.alloc(64)
  this.inner = Sha256()
  this.outer = Sha256()

  const keyhash = b4a.alloc(32)
  if (key.byteLength > 64) {
    Sha256().update(key).digest(keyhash)
    key = keyhash
  }

  this.pad.fill(0x36)
  for (let i = 0; i < key.byteLength; i++) {
    this.pad[i] ^= key[i]
  }
  this.inner.update(this.pad)

  this.pad.fill(0x5c)
  for (let i = 0; i < key.byteLength; i++) {
    this.pad[i] ^= key[i]
  }
  this.outer.update(this.pad)

  this.pad.fill(0)
  keyhash.fill(0)
}

HMAC.prototype.update = function (input, enc) {
  this.inner.update(input, enc)
  return this
}

HMAC.prototype.digest = function (enc, offset = 0) {
  this.outer.update(this.inner.digest())
  return this.outer.digest(enc, offset)
}

Sha256.HMAC = HMAC

function noop () {}

function formatInput (input, enc) {
  var result = b4a.from(input, enc)

  return [result, result.byteLength]
}

// only works for base that is power of 2
function roundUp (n, base) {
  return (n + base - 1) & -base
}

},{"./sha256.js":69,"b4a":4,"nanoassert":51}],69:[function(require,module,exports){
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[Object.keys(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __toBinary = /* @__PURE__ */ (() => {
  var table = new Uint8Array(128);
  for (var i = 0; i < 64; i++)
    table[i < 26 ? i + 65 : i < 52 ? i + 71 : i < 62 ? i - 4 : i * 4 - 205] = i;
  return (base64) => {
    var n = base64.length, bytes2 = new Uint8Array((n - (base64[n - 1] == "=") - (base64[n - 2] == "=")) * 3 / 4 | 0);
    for (var i2 = 0, j = 0; i2 < n; ) {
      var c0 = table[base64.charCodeAt(i2++)], c1 = table[base64.charCodeAt(i2++)];
      var c2 = table[base64.charCodeAt(i2++)], c3 = table[base64.charCodeAt(i2++)];
      bytes2[j++] = c0 << 2 | c1 >> 4;
      bytes2[j++] = c1 << 4 | c2 >> 2;
      bytes2[j++] = c2 << 6 | c3;
    }
    return bytes2;
  };
})();

// wasm-binary:./sha256.wat
var require_sha256 = __commonJS({
  "wasm-binary:./sha256.wat"(exports2, module2) {
    module2.exports = __toBinary("AGFzbQEAAAABNAVgAX8Bf2AIf39/f39/f38AYAR/f39/AX9gEX9/f39/f39/f39/f39/f39/AGAEf39/fwADBgUAAQIDBAUDAQABBikIfwFBAAt/AUEAC38BQQALfwFBAAt/AUEAC38BQQALfwFBAAt/AUEACwcTAgZtZW1vcnkCAAZzaGEyNTYABAreFwUZACAAQf+B/AdxQQh4IABBgP6DeHFBCHdyC7wDAQZ/IwQjBXEjBEF/cyMGcXMhCiMAIwFxIwAjAnFzIwEjAnFzIQsjAEECeCMAQQ14cyMAQRZ4cyEMIwRBBngjBEELeHMjBEEZeHMhDSMHIApqIA1qIABqIARqIQggDCALaiEJIwMgCGokByAIIAlqJAMjByMEcSMHQX9zIwVxcyEKIwMjAHEjAyMBcXMjACMBcXMhCyMDQQJ4IwNBDXhzIwNBFnhzIQwjB0EGeCMHQQt4cyMHQRl4cyENIwYgCmogDWogAWogBWohCCAMIAtqIQkjAiAIaiQGIAggCWokAiMGIwdxIwZBf3MjBHFzIQojAiMDcSMCIwBxcyMDIwBxcyELIwJBAngjAkENeHMjAkEWeHMhDCMGQQZ4IwZBC3hzIwZBGXhzIQ0jBSAKaiANaiACaiAGaiEIIAwgC2ohCSMBIAhqJAUgCCAJaiQBIwUjBnEjBUF/cyMHcXMhCiMBIwJxIwEjA3FzIwIjA3FzIQsjAUECeCMBQQ14cyMBQRZ4cyEMIwVBBngjBUELeHMjBUEZeHMhDSMEIApqIA1qIANqIAdqIQggDCALaiEJIwAgCGokBCAIIAlqJAALKwAgAEEReCAAQRN4cyAAQQp2cyABaiACQQd4IAJBEnhzIAJBA3ZzIANqagvLCwEwfyAAKAJoRQRAIABB58yn0AY2AgAgAEGF3Z7bezYCBCAAQfLmu+MDNgIIIABBuuq/qno2AgwgAEH/pLmIBTYCECAAQYzRldh5NgIUIABBq7OP/AE2AhggAEGZmoPfBTYCHCAAQQE2AmgLIAAoAgAkACAAKAIEJAEgACgCCCQCIAAoAgwkAyAAKAIQJAQgACgCFCQFIAAoAhgkBiAAKAIcJAcgARAAIQEgAhAAIQIgAxAAIQMgBBAAIQQgBRAAIQUgBhAAIQYgBxAAIQcgCBAAIQggCRAAIQkgChAAIQogCxAAIQsgDBAAIQwgDRAAIQ0gDhAAIQ4gDxAAIQ8gEBAAIRAgASACIAMgBEGY36iUBEGRid2JB0HP94Oue0Glt9fNfhABIAUgBiAHIAhB24TbygNB8aPEzwVBpIX+kXlB1b3x2HoQASAJIAogCyAMQZjVnsB9QYG2jZQBQb6LxqECQcP7sagFEAEgDSAOIA8gEEH0uvmVB0H+4/qGeEGnjfDeeUH04u+MfBABIA8gCiACIAEQAiEBIBAgCyADIAIQAiECIAEgDCAEIAMQAiEDIAIgDSAFIAQQAiEEIAMgDiAGIAUQAiEFIAQgDyAHIAYQAiEGIAUgECAIIAcQAiEHIAYgASAJIAgQAiEIIAcgAiAKIAkQAiEJIAggAyALIAoQAiEKIAkgBCAMIAsQAiELIAogBSANIAwQAiEMIAsgBiAOIA0QAiENIAwgByAPIA4QAiEOIA0gCCAQIA8QAiEPIA4gCSABIBAQAiEQIAEgAiADIARBwdPtpH5Bho/5/X5BxruG/gBBzMOyoAIQASAFIAYgByAIQe/YpO8CQaqJ0tMEQdzTwuUFQdqR5rcHEAEgCSAKIAsgDEHSovnBeUHtjMfBekHIz4yAe0HH/+X6exABIA0gDiAPIBBB85eAt3xBx6KerX1B0capNkHn0qShARABIA8gCiACIAEQAiEBIBAgCyADIAIQAiECIAEgDCAEIAMQAiEDIAIgDSAFIAQQAiEEIAMgDiAGIAUQAiEFIAQgDyAHIAYQAiEGIAUgECAIIAcQAiEHIAYgASAJIAgQAiEIIAcgAiAKIAkQAiEJIAggAyALIAoQAiEKIAkgBCAMIAsQAiELIAogBSANIAwQAiEMIAsgBiAOIA0QAiENIAwgByAPIA4QAiEOIA0gCCAQIA8QAiEPIA4gCSABIBAQAiEQIAEgAiADIARBhZXcvQJBuMLs8AJB/Nux6QRBk5rgmQUQASAFIAYgByAIQdTmqagGQbuVqLMHQa6Si454QYXZyJN5EAEgCSAKIAsgDEGh0f+VekHLzOnAekHwlq6SfEGjo7G7fBABIA0gDiAPIBBBmdDLjH1BpIzktH1Bheu4oH9B8MCqgwEQASAPIAogAiABEAIhASAQIAsgAyACEAIhAiABIAwgBCADEAIhAyACIA0gBSAEEAIhBCADIA4gBiAFEAIhBSAEIA8gByAGEAIhBiAFIBAgCCAHEAIhByAGIAEgCSAIEAIhCCAHIAIgCiAJEAIhCSAIIAMgCyAKEAIhCiAJIAQgDCALEAIhCyAKIAUgDSAMEAIhDCALIAYgDiANEAIhDSAMIAcgDyAOEAIhDiANIAggECAPEAIhDyAOIAkgASAQEAIhECABIAIgAyAEQZaCk80BQYjY3fEBQczuoboCQbX5wqUDEAEgBSAGIAcgCEGzmfDIA0HK1OL2BEHPlPPcBUHz37nBBhABIAkgCiALIAxB7oW+pAdB78aVxQdBlPChpnhBiISc5ngQASANIA4gDyAQQfr/+4V5QevZwaJ6QffH5vd7QfLxxbN8EAEgACAAKAIAIwBqNgIAIAAgACgCBCMBajYCBCAAIAAoAggjAmo2AgggACAAKAIMIwNqNgIMIAAgACgCECMEajYCECAAIAAoAhQjBWo2AhQgACAAKAIYIwZqNgIYIAAgACgCHCMHajYCHAuKCAIBfhJ/IAApAyAhBCAEp0E/cSACaiEGIAQgAq18IQQgACAENwMgAkAgACgCKCEHIAAoAiwhCCAAKAIwIQkgACgCNCEKIAAoAjghCyAAKAI8IQwgACgCQCENIAAoAkQhDiAAKAJIIQ8gACgCTCEQIAAoAlAhESAAKAJUIRIgACgCWCETIAAoAlwhFCAAKAJgIRUgACgCZCEWIAZBwABrIgZBAEgNACAAIAcgCCAJIAogCyAMIA0gDiAPIBAgESASIBMgFCAVIBYQAwNAIAEoAgAhByABKAIEIQggASgCCCEJIAEoAgwhCiABKAIQIQsgASgCFCEMIAEoAhghDSABKAIcIQ4gASgCICEPIAEoAiQhECABKAIoIREgASgCLCESIAEoAjAhEyABKAI0IRQgASgCOCEVIAEoAjwhFiABQcAAaiEBIAZBwABrIgZBAEgEQCAAIAc2AiggACAINgIsIAAgCTYCMCAAIAo2AjQgACALNgI4IAAgDDYCPCAAIA02AkAgACAONgJEIAAgDzYCSCAAIBA2AkwgACARNgJQIAAgEjYCVCAAIBM2AlggACAUNgJcIAAgFTYCYCAAIBY2AmQMAgsgACAHIAggCSAKIAsgDCANIA4gDyAQIBEgEiATIBQgFSAWEAMMAAsLIANBAUYEQCAEp0E/cSEGQYABIAZBA3FBA3R0IQUCQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAgBkECdg4PAwQFBgcICQoLDA0ODxABAgsLIAUgFXIhFUEAIQULIAUgFnIhFkEAIQUgACAHIAggCSAKIAsgDCANIA4gDyAQIBEgEiATIBQgFSAWEAMgACAENwMgQQAhB0EAIQhBACEJQQAhCkEAIQtBACEMQQAhDUEAIQ5BACEPQQAhEEEAIRFBACESQQAhE0EAIRRBACEVQQAhFgsgBSAHciEHQQAhBQsgBSAIciEIQQAhBQsgBSAJciEJQQAhBQsgBSAKciEKQQAhBQsgBSALciELQQAhBQsgBSAMciEMQQAhBQsgBSANciENQQAhBQsgBSAOciEOQQAhBQsgBSAPciEPQQAhBQsgBSAQciEQQQAhBQsgBSARciERQQAhBQsgBSASciESQQAhBQsgBSATciETQQAhBQsgBSAUciEUQQAhBQsgBEIdiKcQACEVIARCA4anEAAhFiAAIAcgCCAJIAogCyAMIA0gDiAPIBAgESASIBMgFCAVIBYQAyAAIAAoAgAQADYCACAAIAAoAgQQADYCBCAAIAAoAggQADYCCCAAIAAoAgwQADYCDCAAIAAoAhAQADYCECAAIAAoAhQQADYCFCAAIAAoAhgQADYCGCAAIAAoAhwQADYCHAsL");
  }
});

// wasm-module:./sha256.wat
var bytes = require_sha256();
var compiled = new WebAssembly.Module(bytes);
module.exports = (imports) => {
  const instance = new WebAssembly.Instance(compiled, imports);
  return instance.exports;
};

},{}],70:[function(require,module,exports){
const js = require('./sha512.js')
const wasm = require('sha512-wasm')

var Proto = js

module.exports = function () {
  return new Proto()
}

module.exports.ready = function (cb) {
  wasm.ready(function () { // ignore errors
    cb()
  })
}

module.exports.WASM_SUPPORTED = wasm.SUPPORTED
module.exports.WASM_LOADED = false

var SHA512_BYTES = module.exports.SHA512_BYTES = 64

wasm.ready(function (err) {
  if (!err) {
    module.exports.WASM_LOADED = true
    module.exports = Proto = wasm
  }
})

},{"./sha512.js":71,"sha512-wasm":72}],71:[function(require,module,exports){
const assert = require('nanoassert')
const b4a = require('b4a')

module.exports = Sha512

const BLOCKSIZE = 128

var K = [
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
  0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
  0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
  0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
  0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
  0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
  0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
  0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
  0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
  0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
  0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
  0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
  0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
  0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
  0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
  0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
  0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
  0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
  0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
  0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
  0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
]

function Sha512 () {
  if (!(this instanceof Sha512)) return new Sha512()

  this.hh = new Int32Array(8)
  this.hl = new Int32Array(8)
  this.buffer = new Uint8Array(128)
  this.finalised = false
  this.bytesRead = 0
  this.pos = 0

  this.hh[0] = 0x6a09e667
  this.hh[1] = 0xbb67ae85
  this.hh[2] = 0x3c6ef372
  this.hh[3] = 0xa54ff53a
  this.hh[4] = 0x510e527f
  this.hh[5] = 0x9b05688c
  this.hh[6] = 0x1f83d9ab
  this.hh[7] = 0x5be0cd19

  this.hl[0] = 0xf3bcc908
  this.hl[1] = 0x84caa73b
  this.hl[2] = 0xfe94f82b
  this.hl[3] = 0x5f1d36f1
  this.hl[4] = 0xade682d1
  this.hl[5] = 0x2b3e6c1f
  this.hl[6] = 0xfb41bd6b
  this.hl[7] = 0x137e2179

  return this
}

Sha512.prototype.update = function (input, enc) {
  assert(this.finalised === false, 'Hash instance finalised')

  var [inputBuf, len] = formatInput(input, enc)
  this.bytesRead += len

  const full = (len + this.pos) & -128

  this.buffer.set(inputBuf.subarray(0, BLOCKSIZE - this.pos), this.pos)
  const pos = this.pos
  len -= BLOCKSIZE - this.pos

  if (len >= 0) {
    compress(this.hh, this.hl, this.buffer, 128)
    this.pos = 0
  }

  if (len > 127) {
    compress(this.hh, this.hl, inputBuf.subarray(BLOCKSIZE - pos, full - pos), full - BLOCKSIZE)
    len %= 128
  }

  this.buffer.set(inputBuf.subarray(inputBuf.byteLength - len))
  this.pos = this.bytesRead & 0x7f
  this.buffer.fill(0, this.pos)

  return this
}

Sha512.prototype.digest = function (enc, offset = 0) {
  assert(this.finalised === false, 'Hash instance finalised')
  this.finalised = true

  this.buffer.fill(0, this.pos)
  this.buffer[this.pos] = 128

  if (this.pos > 111) {
    compress(this.hh, this.hl, this.buffer, 128)

    this.buffer.fill(0)
    this.pos = 0
  }

  ts64(this.buffer, 120, (this.bytesRead / 0x20000000) | 0, this.bytesRead << 3)
  compress(this.hh, this.hl, this.buffer, 128)

  if (enc instanceof Uint8Array && enc.byteLength > 63) {
    for (let i = 0; i < 8; i++) ts64(enc, 8 * i + offset, this.hh[i], this.hl[i])
    return enc
  }

  const resultBuf = new Uint8Array(64)
  for (let i = 0; i < 8; i++) ts64(resultBuf, 8 * i, this.hh[i], this.hl[i])

  if (typeof enc === 'string') {
    return b4a.toString(resultBuf, enc)
  }

  return resultBuf
}

function ts64 (x, i, h, l) {
  x[i] = (h >> 24) & 0xff
  x[i + 1] = (h >> 16) & 0xff
  x[i + 2] = (h >> 8) & 0xff
  x[i + 3] = h & 0xff
  x[i + 4] = (l >> 24) & 0xff
  x[i + 5] = (l >> 16) & 0xff
  x[i + 6] = (l >> 8) & 0xff
  x[i + 7] = l & 0xff
}

function formatInput (input, enc) {
  var result = b4a.from(input, enc)

  return [result, result.byteLength]
}

function compress(hh, hl, m, n) {
  var wh = new Int32Array(16), wl = new Int32Array(16),
      bh0, bh1, bh2, bh3, bh4, bh5, bh6, bh7,
      bl0, bl1, bl2, bl3, bl4, bl5, bl6, bl7,
      th, tl, i, j, h, l, a, b, c, d;

  var ah0 = hh[0],
      ah1 = hh[1],
      ah2 = hh[2],
      ah3 = hh[3],
      ah4 = hh[4],
      ah5 = hh[5],
      ah6 = hh[6],
      ah7 = hh[7],

      al0 = hl[0],
      al1 = hl[1],
      al2 = hl[2],
      al3 = hl[3],
      al4 = hl[4],
      al5 = hl[5],
      al6 = hl[6],
      al7 = hl[7];

  var pos = 0;
  while (n >= 128) {
    for (i = 0; i < 16; i++) {
      j = 8 * i + pos;
      wh[i] = (m[j+0] << 24) | (m[j+1] << 16) | (m[j+2] << 8) | m[j+3];
      wl[i] = (m[j+4] << 24) | (m[j+5] << 16) | (m[j+6] << 8) | m[j+7];
    }
    for (i = 0; i < 80; i++) {
      bh0 = ah0;
      bh1 = ah1;
      bh2 = ah2;
      bh3 = ah3;
      bh4 = ah4;
      bh5 = ah5;
      bh6 = ah6;
      bh7 = ah7;

      bl0 = al0;
      bl1 = al1;
      bl2 = al2;
      bl3 = al3;
      bl4 = al4;
      bl5 = al5;
      bl6 = al6;
      bl7 = al7;

      // add
      h = ah7;
      l = al7;

      a = l & 0xffff; b = l >>> 16;
      c = h & 0xffff; d = h >>> 16;

      // Sigma1
      h = ((ah4 >>> 14) | (al4 << (32-14))) ^ ((ah4 >>> 18) | (al4 << (32-18))) ^ ((al4 >>> (41-32)) | (ah4 << (32-(41-32))));
      l = ((al4 >>> 14) | (ah4 << (32-14))) ^ ((al4 >>> 18) | (ah4 << (32-18))) ^ ((ah4 >>> (41-32)) | (al4 << (32-(41-32))));

      a += l & 0xffff; b += l >>> 16;
      c += h & 0xffff; d += h >>> 16;

      // Ch
      h = (ah4 & ah5) ^ (~ah4 & ah6);
      l = (al4 & al5) ^ (~al4 & al6);

      a += l & 0xffff; b += l >>> 16;
      c += h & 0xffff; d += h >>> 16;

      // K
      h = K[i*2];
      l = K[i*2+1];

      a += l & 0xffff; b += l >>> 16;
      c += h & 0xffff; d += h >>> 16;

      // w
      h = wh[i%16];
      l = wl[i%16];

      a += l & 0xffff; b += l >>> 16;
      c += h & 0xffff; d += h >>> 16;

      b += a >>> 16;
      c += b >>> 16;
      d += c >>> 16;

      th = c & 0xffff | d << 16;
      tl = a & 0xffff | b << 16;

      // add
      h = th;
      l = tl;

      a = l & 0xffff; b = l >>> 16;
      c = h & 0xffff; d = h >>> 16;

      // Sigma0
      h = ((ah0 >>> 28) | (al0 << (32-28))) ^ ((al0 >>> (34-32)) | (ah0 << (32-(34-32)))) ^ ((al0 >>> (39-32)) | (ah0 << (32-(39-32))));
      l = ((al0 >>> 28) | (ah0 << (32-28))) ^ ((ah0 >>> (34-32)) | (al0 << (32-(34-32)))) ^ ((ah0 >>> (39-32)) | (al0 << (32-(39-32))));

      a += l & 0xffff; b += l >>> 16;
      c += h & 0xffff; d += h >>> 16;

      // Maj
      h = (ah0 & ah1) ^ (ah0 & ah2) ^ (ah1 & ah2);
      l = (al0 & al1) ^ (al0 & al2) ^ (al1 & al2);

      a += l & 0xffff; b += l >>> 16;
      c += h & 0xffff; d += h >>> 16;

      b += a >>> 16;
      c += b >>> 16;
      d += c >>> 16;

      bh7 = (c & 0xffff) | (d << 16);
      bl7 = (a & 0xffff) | (b << 16);

      // add
      h = bh3;
      l = bl3;

      a = l & 0xffff; b = l >>> 16;
      c = h & 0xffff; d = h >>> 16;

      h = th;
      l = tl;

      a += l & 0xffff; b += l >>> 16;
      c += h & 0xffff; d += h >>> 16;

      b += a >>> 16;
      c += b >>> 16;
      d += c >>> 16;

      bh3 = (c & 0xffff) | (d << 16);
      bl3 = (a & 0xffff) | (b << 16);

      ah1 = bh0;
      ah2 = bh1;
      ah3 = bh2;
      ah4 = bh3;
      ah5 = bh4;
      ah6 = bh5;
      ah7 = bh6;
      ah0 = bh7;

      al1 = bl0;
      al2 = bl1;
      al3 = bl2;
      al4 = bl3;
      al5 = bl4;
      al6 = bl5;
      al7 = bl6;
      al0 = bl7;

      if (i%16 === 15) {
        for (j = 0; j < 16; j++) {
          // add
          h = wh[j];
          l = wl[j];

          a = l & 0xffff; b = l >>> 16;
          c = h & 0xffff; d = h >>> 16;

          h = wh[(j+9)%16];
          l = wl[(j+9)%16];

          a += l & 0xffff; b += l >>> 16;
          c += h & 0xffff; d += h >>> 16;

          // sigma0
          th = wh[(j+1)%16];
          tl = wl[(j+1)%16];
          h = ((th >>> 1) | (tl << (32-1))) ^ ((th >>> 8) | (tl << (32-8))) ^ (th >>> 7);
          l = ((tl >>> 1) | (th << (32-1))) ^ ((tl >>> 8) | (th << (32-8))) ^ ((tl >>> 7) | (th << (32-7)));

          a += l & 0xffff; b += l >>> 16;
          c += h & 0xffff; d += h >>> 16;

          // sigma1
          th = wh[(j+14)%16];
          tl = wl[(j+14)%16];
          h = ((th >>> 19) | (tl << (32-19))) ^ ((tl >>> (61-32)) | (th << (32-(61-32)))) ^ (th >>> 6);
          l = ((tl >>> 19) | (th << (32-19))) ^ ((th >>> (61-32)) | (tl << (32-(61-32)))) ^ ((tl >>> 6) | (th << (32-6)));

          a += l & 0xffff; b += l >>> 16;
          c += h & 0xffff; d += h >>> 16;

          b += a >>> 16;
          c += b >>> 16;
          d += c >>> 16;

          wh[j] = (c & 0xffff) | (d << 16);
          wl[j] = (a & 0xffff) | (b << 16);
        }
      }
    }

    // add
    h = ah0;
    l = al0;

    a = l & 0xffff; b = l >>> 16;
    c = h & 0xffff; d = h >>> 16;

    h = hh[0];
    l = hl[0];

    a += l & 0xffff; b += l >>> 16;
    c += h & 0xffff; d += h >>> 16;

    b += a >>> 16;
    c += b >>> 16;
    d += c >>> 16;

    hh[0] = ah0 = (c & 0xffff) | (d << 16);
    hl[0] = al0 = (a & 0xffff) | (b << 16);

    h = ah1;
    l = al1;

    a = l & 0xffff; b = l >>> 16;
    c = h & 0xffff; d = h >>> 16;

    h = hh[1];
    l = hl[1];

    a += l & 0xffff; b += l >>> 16;
    c += h & 0xffff; d += h >>> 16;

    b += a >>> 16;
    c += b >>> 16;
    d += c >>> 16;

    hh[1] = ah1 = (c & 0xffff) | (d << 16);
    hl[1] = al1 = (a & 0xffff) | (b << 16);

    h = ah2;
    l = al2;

    a = l & 0xffff; b = l >>> 16;
    c = h & 0xffff; d = h >>> 16;

    h = hh[2];
    l = hl[2];

    a += l & 0xffff; b += l >>> 16;
    c += h & 0xffff; d += h >>> 16;

    b += a >>> 16;
    c += b >>> 16;
    d += c >>> 16;

    hh[2] = ah2 = (c & 0xffff) | (d << 16);
    hl[2] = al2 = (a & 0xffff) | (b << 16);

    h = ah3;
    l = al3;

    a = l & 0xffff; b = l >>> 16;
    c = h & 0xffff; d = h >>> 16;

    h = hh[3];
    l = hl[3];

    a += l & 0xffff; b += l >>> 16;
    c += h & 0xffff; d += h >>> 16;

    b += a >>> 16;
    c += b >>> 16;
    d += c >>> 16;

    hh[3] = ah3 = (c & 0xffff) | (d << 16);
    hl[3] = al3 = (a & 0xffff) | (b << 16);

    h = ah4;
    l = al4;

    a = l & 0xffff; b = l >>> 16;
    c = h & 0xffff; d = h >>> 16;

    h = hh[4];
    l = hl[4];

    a += l & 0xffff; b += l >>> 16;
    c += h & 0xffff; d += h >>> 16;

    b += a >>> 16;
    c += b >>> 16;
    d += c >>> 16;

    hh[4] = ah4 = (c & 0xffff) | (d << 16);
    hl[4] = al4 = (a & 0xffff) | (b << 16);

    h = ah5;
    l = al5;

    a = l & 0xffff; b = l >>> 16;
    c = h & 0xffff; d = h >>> 16;

    h = hh[5];
    l = hl[5];

    a += l & 0xffff; b += l >>> 16;
    c += h & 0xffff; d += h >>> 16;

    b += a >>> 16;
    c += b >>> 16;
    d += c >>> 16;

    hh[5] = ah5 = (c & 0xffff) | (d << 16);
    hl[5] = al5 = (a & 0xffff) | (b << 16);

    h = ah6;
    l = al6;

    a = l & 0xffff; b = l >>> 16;
    c = h & 0xffff; d = h >>> 16;

    h = hh[6];
    l = hl[6];

    a += l & 0xffff; b += l >>> 16;
    c += h & 0xffff; d += h >>> 16;

    b += a >>> 16;
    c += b >>> 16;
    d += c >>> 16;

    hh[6] = ah6 = (c & 0xffff) | (d << 16);
    hl[6] = al6 = (a & 0xffff) | (b << 16);

    h = ah7;
    l = al7;

    a = l & 0xffff; b = l >>> 16;
    c = h & 0xffff; d = h >>> 16;

    h = hh[7];
    l = hl[7];

    a += l & 0xffff; b += l >>> 16;
    c += h & 0xffff; d += h >>> 16;

    b += a >>> 16;
    c += b >>> 16;
    d += c >>> 16;

    hh[7] = ah7 = (c & 0xffff) | (d << 16);
    hl[7] = al7 = (a & 0xffff) | (b << 16);

    pos += 128;
    n -= 128;
  }
}

function HMAC (key) {
  if (!(this instanceof HMAC)) return new HMAC(key)

  this.pad = b4a.alloc(128)
  this.inner = Sha512()
  this.outer = Sha512()

  const keyhash = b4a.alloc(64)
  if (key.byteLength > 128) {
    Sha512().update(key).digest(keyhash)
    key = keyhash
  }

  this.pad.fill(0x36)
  for (let i = 0; i < key.byteLength; i++) {
    this.pad[i] ^= key[i]
  }
  this.inner.update(this.pad)

  this.pad.fill(0x5c)
  for (let i = 0; i < key.byteLength; i++) {
    this.pad[i] ^= key[i]
  }
  this.outer.update(this.pad)

  this.pad.fill(0)
  keyhash.fill(0)
}

HMAC.prototype.update = function (input, enc) {
  this.inner.update(input, enc)
  return this
}

HMAC.prototype.digest = function (enc, offset = 0) {
  this.outer.update(this.inner.digest())
  return this.outer.digest(enc, offset)
}

Sha512.HMAC = HMAC

},{"b4a":4,"nanoassert":51}],72:[function(require,module,exports){
const assert = require('nanoassert')
const b4a = require('b4a')

const wasm = typeof WebAssembly !== 'undefined' && require('./sha512.js')({
  imports: {
    debug: {
      log (...args) {
        console.log(...args.map(int => (int >>> 0).toString(16).padStart(8, '0')))
      },
      log_tee (arg) {
        console.log((arg >>> 0).toString(16).padStart(8, '0'))
        return arg
      }
    }
  }
})

let head = 0
// assetrt head % 8 === 0 to guarantee alignment
const freeList = []

module.exports = Sha512
const SHA512_BYTES = module.exports.SHA512_BYTES = 64
const INPUT_OFFSET = 80
const STATEBYTES = 216
const BLOCKSIZE = 128

function Sha512 () {
  if (!(this instanceof Sha512)) return new Sha512()
  if (!(wasm)) throw new Error('WASM not loaded. Wait for Sha512.ready(cb)')

  if (!freeList.length) {
    freeList.push(head)
    head += STATEBYTES
  }

  this.finalized = false
  this.digestLength = SHA512_BYTES
  this.pointer = freeList.pop()
  this.pos = 0
  this.wasm = wasm

  this._memory = new Uint8Array(wasm.memory.buffer)
  this._memory.fill(0, this.pointer, this.pointer + STATEBYTES)

  if (this.pointer + this.digestLength > this._memory.length) this._realloc(this.pointer + STATEBYTES)
}

Sha512.prototype._realloc = function (size) {
  wasm.memory.grow(Math.max(0, Math.ceil(Math.abs(size - this._memory.length) / 65536)))
  this._memory = new Uint8Array(wasm.memory.buffer)
}

Sha512.prototype.update = function (input, enc) {
  assert(this.finalized === false, 'Hash instance finalized')

  if (head % 8 !== 0) head += 8 - head % 8
  assert(head % 8 === 0, 'input should be aligned for int64')

  const [inputBuf, length] = formatInput(input, enc)

  assert(inputBuf instanceof Uint8Array, 'input must be Uint8Array or Buffer')

  if (head + input.length > this._memory.length) this._realloc(head + input.length)

  this._memory.fill(0, head, head + roundUp(length, BLOCKSIZE) - BLOCKSIZE)
  this._memory.set(inputBuf.subarray(0, BLOCKSIZE - this.pos), this.pointer + INPUT_OFFSET + this.pos)
  this._memory.set(inputBuf.subarray(BLOCKSIZE - this.pos), head)

  this.pos = (this.pos + length) & 0x7f
  wasm.sha512(this.pointer, head, length, 0)

  return this
}

Sha512.prototype.digest = function (enc, offset = 0) {
  assert(this.finalized === false, 'Hash instance finalized')

  this.finalized = true
  freeList.push(this.pointer)

  const paddingStart = this.pointer + INPUT_OFFSET + this.pos
  this._memory.fill(0, paddingStart, this.pointer + INPUT_OFFSET + BLOCKSIZE)
  wasm.sha512(this.pointer, head, 0, 1)

  const resultBuf = this._memory.subarray(this.pointer, this.pointer + this.digestLength)

  if (!enc) {
    return resultBuf
  }

  if (typeof enc === 'string') {
    return b4a.toString(resultBuf, enc)
  }

  assert(enc instanceof Uint8Array, 'output must be Uint8Array or Buffer')
  assert(enc.byteLength >= this.digestLength + offset,
    "output must have at least 'SHA512_BYTES' bytes remaining")

  for (let i = 0; i < this.digestLength; i++) {
    enc[i + offset] = resultBuf[i]
  }

  return enc
}

Sha512.WASM = wasm
Sha512.WASM_SUPPORTED = typeof WebAssembly !== 'undefined'

Sha512.ready = function (cb) {
  if (!cb) cb = noop
  if (!wasm) return cb(new Error('WebAssembly not supported'))
  cb()
  return Promise.resolve()
}

Sha512.prototype.ready = Sha512.ready

function HMAC (key) {
  if (!(this instanceof HMAC)) return new HMAC(key)

  this.pad = b4a.alloc(128)
  this.inner = Sha512()
  this.outer = Sha512()

  const keyhash = b4a.alloc(64)
  if (key.byteLength > 128) {
    Sha512().update(key).digest(keyhash)
    key = keyhash
  }

  this.pad.fill(0x36)
  for (let i = 0; i < key.byteLength; i++) {
    this.pad[i] ^= key[i]
  }
  this.inner.update(this.pad)

  this.pad.fill(0x5c)
  for (let i = 0; i < key.byteLength; i++) {
    this.pad[i] ^= key[i]
  }
  this.outer.update(this.pad)

  this.pad.fill(0)
  keyhash.fill(0)
}

HMAC.prototype.update = function (input, enc) {
  this.inner.update(input, enc)
  return this
}

HMAC.prototype.digest = function (enc, offset = 0) {
  this.outer.update(this.inner.digest())
  return this.outer.digest(enc, offset)
}

Sha512.HMAC = HMAC

function noop () {}

function formatInput (input, enc) {
  var result = b4a.from(input, enc)

  return [result, result.byteLength]
}

// only works for base that is power of 2
function roundUp (n, base) {
  return (n + base - 1) & -base
}

},{"./sha512.js":73,"b4a":4,"nanoassert":51}],73:[function(require,module,exports){
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[Object.keys(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __toBinary = /* @__PURE__ */ (() => {
  var table = new Uint8Array(128);
  for (var i = 0; i < 64; i++)
    table[i < 26 ? i + 65 : i < 52 ? i + 71 : i < 62 ? i - 4 : i * 4 - 205] = i;
  return (base64) => {
    var n = base64.length, bytes2 = new Uint8Array((n - (base64[n - 1] == "=") - (base64[n - 2] == "=")) * 3 / 4 | 0);
    for (var i2 = 0, j = 0; i2 < n; ) {
      var c0 = table[base64.charCodeAt(i2++)], c1 = table[base64.charCodeAt(i2++)];
      var c2 = table[base64.charCodeAt(i2++)], c3 = table[base64.charCodeAt(i2++)];
      bytes2[j++] = c0 << 2 | c1 >> 4;
      bytes2[j++] = c1 << 4 | c2 >> 2;
      bytes2[j++] = c2 << 6 | c3;
    }
    return bytes2;
  };
})();

// wasm-binary:./sha512.wat
var require_sha512 = __commonJS({
  "wasm-binary:./sha512.wat"(exports2, module2) {
    module2.exports = __toBinary("AGFzbQEAAAABNAVgAX4BfmAIfn5+fn5+fn4AYAR+fn5+AX5gEX9+fn5+fn5+fn5+fn5+fn5+AGAEf39/fwADBgUAAQIDBAUDAQABBikIfgFCAAt+AUIAC34BQgALfgFCAAt+AUIAC34BQgALfgFCAAt+AUIACwcTAgZtZW1vcnkCAAZzaGE1MTIABAqZHgVCACAAQoCA/P+PgECDQhCJIABC//+DgPD/P4NCEIqEIQAgAEL/gfyH8J/A/wCDQgiJIABCgP6D+I/gv4B/g0IIioQLvAMBBn4jBCMFgyMEQn+FIwaDhSEKIwAjAYMjACMCg4UjASMCg4UhCyMAQhyKIwBCIoqFIwBCJ4qFIQwjBEIOiiMEQhKKhSMEQimKhSENIwcgCnwgDXwgAHwgBHwhCCAMIAt8IQkjAyAIfCQHIAggCXwkAyMHIwSDIwdCf4UjBYOFIQojAyMAgyMDIwGDhSMAIwGDhSELIwNCHIojA0IiioUjA0InioUhDCMHQg6KIwdCEoqFIwdCKYqFIQ0jBiAKfCANfCABfCAFfCEIIAwgC3whCSMCIAh8JAYgCCAJfCQCIwYjB4MjBkJ/hSMEg4UhCiMCIwODIwIjAIOFIwMjAIOFIQsjAkIciiMCQiKKhSMCQieKhSEMIwZCDoojBkISioUjBkIpioUhDSMFIAp8IA18IAJ8IAZ8IQggDCALfCEJIwEgCHwkBSAIIAl8JAEjBSMGgyMFQn+FIweDhSEKIwEjAoMjASMDg4UjAyMCg4UhCyMBQhyKIwFCIoqFIwFCJ4qFIQwjBUIOiiMFQhKKhSMFQimKhSENIwQgCnwgDXwgA3wgB3whCCAMIAt8IQkjACAIfCQEIAggCXwkAAsrACAAQhOKIABCPYqFIABCBoiFIAF8IAJCAYogAkIIioUgAkIHiIUgA3x8C6QRACAAKQPQAUIAUQRAIABCiJLznf/M+YTqADcDACAAQrvOqqbY0Ouzu383AwggAEKr8NP0r+68tzw3AxAgAELx7fT4paf9p6V/NwMYIABC0YWa7/rPlIfRADcDICAAQp/Y+dnCkdqCm383AyggAELr+obav7X2wR83AzAgAEL5wvibkaOz8NsANwM4IABCATcD0AELIAApAwAkACAAKQMIJAEgACkDECQCIAApAxgkAyAAKQMgJAQgACkDKCQFIAApAzAkBiAAKQM4JAcgARAAIQEgAhAAIQIgAxAAIQMgBBAAIQQgBRAAIQUgBhAAIQYgBxAAIQcgCBAAIQggCRAAIQkgChAAIQogCxAAIQsgDBAAIQwgDRAAIQ0gDhAAIQ4gDxAAIQ8gEBAAIRAgASACIAMgBEKi3KK5jfOLxcIAQs3LvZ+SktGb8QBCr/a04v75vuC1f0K8t6eM2PT22mkQASAFIAYgByAIQrjqopq/y7CrOUKZoJewm77E+NkAQpuf5fjK1OCfkn9CmIK2093al46rfxABIAkgCiALIAxCwoSMmIrT6oNYQr7fwauU4NbBEkKM5ZL35LfhmCRC4un+r724n4bVABABIA0gDiAPIBBC75Luk8+ul9/yAEKxrdrY47+s74B/QrWknK7y1IHum39ClM2k+8yu/M1BEAEgDyAKIAIgARACIQEgECALIAMgAhACIQIgASAMIAQgAxACIQMgAiANIAUgBBACIQQgAyAOIAYgBRACIQUgBCAPIAcgBhACIQYgBSAQIAggBxACIQcgBiABIAkgCBACIQggByACIAogCRACIQkgCCADIAsgChACIQogCSAEIAwgCxACIQsgCiAFIA0gDBACIQwgCyAGIA4gDRACIQ0gDCAHIA8gDhACIQ4gDSAIIBAgDxACIQ8gDiAJIAEgEBACIRAgASACIAMgBELSlcX3mbjazWRC48u8wuPwkd9vQrWrs9zouOfgD0LluLK9x7mohiQQASAFIAYgByAIQvWErMn1jcv0LUKDyZv1ppWhusoAQtT3h+rLu6rY3ABCtafFmKib4vz2ABABIAkgCiALIAxCq7+b866qlJ+Yf0KQ5NDt0s3xmKh/Qr/C7MeJ+cmBsH9C5J289/v436y/fxABIA0gDiAPIBBCwp+i7bP+gvBGQqXOqpj5qOTTVULvhI6AnuqY5QZC8Ny50PCsypQUEAEgDyAKIAIgARACIQEgECALIAMgAhACIQIgASAMIAQgAxACIQMgAiANIAUgBBACIQQgAyAOIAYgBRACIQUgBCAPIAcgBhACIQYgBSAQIAggBxACIQcgBiABIAkgCBACIQggByACIAogCRACIQkgCCADIAsgChACIQogCSAEIAwgCxACIQsgCiAFIA0gDBACIQwgCyAGIA4gDRACIQ0gDCAHIA8gDhACIQ4gDSAIIBAgDxACIQ8gDiAJIAEgEBACIRAgASACIAMgBEL838i21NDC2ydCppKb4YWnyI0uQu3VkNbFv5uWzQBC3+fW7Lmig5zTABABIAUgBiAHIAhC3se93cjqnIXlAEKo5d7js9eCtfYAQubdtr/kpbLhgX9Cu+qIpNGQi7mSfxABIAkgCiALIAxC5IbE55SU+t+if0KB4Ijiu8mZjah/QpGv4oeN7uKlQkKw/NKysLSUtkcQASANIA4gDyAQQpikvbedg7rJUUKQ0parxcTBzFZCqsDEu9WwjYd0Qrij75WDjqi1EBABIA8gCiACIAEQAiEBIBAgCyADIAIQAiECIAEgDCAEIAMQAiEDIAIgDSAFIAQQAiEEIAMgDiAGIAUQAiEFIAQgDyAHIAYQAiEGIAUgECAIIAcQAiEHIAYgASAJIAgQAiEIIAcgAiAKIAkQAiEJIAggAyALIAoQAiEKIAkgBCAMIAsQAiELIAogBSANIAwQAiEMIAsgBiAOIA0QAiENIAwgByAPIA4QAiEOIA0gCCAQIA8QAiEPIA4gCSABIBAQAiEQIAEgAiADIARCyKHLxuuisNIZQtPWhoqFgdubHkKZ17v8zemdpCdCqJHtjN6Wr9g0EAEgBSAGIAcgCELjtKWuvJaDjjlCy5WGmq7JquzOAELzxo+798myztsAQqPxyrW9/puX6AAQASAJIAogCyAMQvzlvu/l3eDH9ABC4N7cmPTt2NL4AELy1sKPyoKe5IR/QuzzkNOBwcDjjH8QASANIA4gDyAQQqi8jJui/7/fkH9C6fuK9L2dm6ikf0KV8pmW+/7o/L5/QqumyZuunt64RhABIA8gCiACIAEQAiEBIBAgCyADIAIQAiECIAEgDCAEIAMQAiEDIAIgDSAFIAQQAiEEIAMgDiAGIAUQAiEFIAQgDyAHIAYQAiEGIAUgECAIIAcQAiEHIAYgASAJIAgQAiEIIAcgAiAKIAkQAiEJIAggAyALIAoQAiEKIAkgBCAMIAsQAiELIAogBSANIAwQAiEMIAsgBiAOIA0QAiENIAwgByAPIA4QAiEOIA0gCCAQIA8QAiEPIA4gCSABIBAQAiEQIAEgAiADIARCnMOZ0e7Zz5NKQoeEg47ymK7DUUKe1oPv7Lqf7WpC+KK78/7v0751EAEgBSAGIAcgCEK6392Qp/WZ+AZCprGiltq437EKQq6b5PfLgOafEUKbjvGY0ebCuBsQASAJIAogCyAMQoT7kZjS/t3tKEKTyZyGtO+q5TJCvP2mrqHBr888QsyawODJ+NmOwwAQASANIA4gDyAQQraF+dnsl/XizABCqvyV48+zyr/ZAELs9dvWs/Xb5d8AQpewndLEsYai7AAQASAAIAApAwAjAHw3AwAgACAAKQMIIwF8NwMIIAAgACkDECMCfDcDECAAIAApAxgjA3w3AxggACAAKQMgIwR8NwMgIAAgACkDKCMFfDcDKCAAIAApAzAjBnw3AzAgACAAKQM4Iwd8NwM4C8MIARV+IAApA0AhBCAAKQNIIQUgBEL/AIMgAq18IQggBCEGIAQgAq18IQQgACAENwNAIAQgBlQEQCAFQgF8IQUgACAFNwNICwJAIAApA1AhCSAAKQNYIQogACkDYCELIAApA2ghDCAAKQNwIQ0gACkDeCEOIAApA4ABIQ8gACkDiAEhECAAKQOQASERIAApA5gBIRIgACkDoAEhEyAAKQOoASEUIAApA7ABIRUgACkDuAEhFiAAKQPAASEXIAApA8gBIRggCEKAAX0iCEIAUw0AIAAgCSAKIAsgDCANIA4gDyAQIBEgEiATIBQgFSAWIBcgGBADA0AgASkDACEJIAEpAwghCiABKQMQIQsgASkDGCEMIAEpAyAhDSABKQMoIQ4gASkDMCEPIAEpAzghECABKQNAIREgASkDSCESIAEpA1AhEyABKQNYIRQgASkDYCEVIAEpA2ghFiABKQNwIRcgASkDeCEYIAFBgAFqIQEgCEKAAX0iCEIAUwRAIAAgCTcDUCAAIAo3A1ggACALNwNgIAAgDDcDaCAAIA03A3AgACAONwN4IAAgDzcDgAEgACAQNwOIASAAIBE3A5ABIAAgEjcDmAEgACATNwOgASAAIBQ3A6gBIAAgFTcDsAEgACAWNwO4ASAAIBc3A8ABIAAgGDcDyAEMAgsgACAJIAogCyAMIA0gDiAPIBAgESASIBMgFCAVIBYgFyAYEAMMAAsLIANBAUYEQCAEQv8AgyEIQoABIAhCB4NCA4aGIQcCQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAgCKdBA3YODwMEBQYHCAkKCwwNDg8QAQILCyAHIBeEIRdCACEHCyAHIBiEIRhCACEHIAAgCSAKIAsgDCANIA4gDyAQIBEgEiATIBQgFSAWIBcgGBADIAAgBDcDQEIAIQlCACEKQgAhC0IAIQxCACENQgAhDkIAIQ9CACEQQgAhEUIAIRJCACETQgAhFEIAIRVCACEWQgAhF0IAIRgLIAcgCYQhCUIAIQcLIAcgCoQhCkIAIQcLIAcgC4QhC0IAIQcLIAcgDIQhDEIAIQcLIAcgDYQhDUIAIQcLIAcgDoQhDkIAIQcLIAcgD4QhD0IAIQcLIAcgEIQhEEIAIQcLIAcgEYQhEUIAIQcLIAcgEoQhEkIAIQcLIAcgE4QhE0IAIQcLIAcgFIQhFEIAIQcLIAcgFYQhFUIAIQcLIAcgFoQhFkIAIQcLIARCPYggBUIDiHwQACEXIARCCH4QACEYIAAgCSAKIAsgDCANIA4gDyAQIBEgEiATIBQgFSAWIBcgGBADIAAgACkDABAANwMAIAAgACkDCBAANwMIIAAgACkDEBAANwMQIAAgACkDGBAANwMYIAAgACkDIBAANwMgIAAgACkDKBAANwMoIAAgACkDMBAANwMwIAAgACkDOBAANwM4Cws=");
  }
});

// wasm-module:./sha512.wat
var bytes = require_sha512();
var compiled = new WebAssembly.Module(bytes);
module.exports = (imports) => {
  const instance = new WebAssembly.Instance(compiled, imports);
  return instance.exports;
};

},{}],74:[function(require,module,exports){
const b4a = require('b4a')
const scalar = require('./scalar')

function view (buf, n) {
  if (n === buf.BYTES_PER_ELEMENT) return buf

  let TypedArray

  if (n === 1) TypedArray = Uint8Array
  else if (n === 2) TypedArray = Uint16Array
  else TypedArray = Uint32Array

  return new TypedArray(buf.buffer, buf.byteOffset, buf.byteLength / n)
}

function unary (u8, u16 = u8, u32 = u16) {
  return function unary (buf, result = b4a.allocUnsafe(buf.byteLength)) {
    if (buf.byteLength % 16 !== 0) {
      throw new Error('Buffer length must be a multiple of 16')
    }

    if (buf.byteLength !== result.byteLength) {
      throw new Error('Length of result buffer is insufficient')
    }

    const n = buf.BYTES_PER_ELEMENT

    if (n === 1) u8(buf, view(result, n))
    else if (n === 2) u16(buf, view(result, n))
    else u32(buf, view(result, n))

    return result
  }
}

function binary (u8, u16 = u8, u32 = u16) {
  return function binary (a, b, result = b4a.allocUnsafe(a.byteLength)) {
    if (a.byteLength % 16 !== 0) {
      throw new Error('Buffer length must be a multiple of 16')
    }

    if (a.byteLength !== b.byteLength || a.byteLength !== result.byteLength) {
      throw new Error('Buffers must be the same length')
    }

    const n = a.BYTES_PER_ELEMENT

    if (n === 1) u8(a, b, view(result, n))
    else if (n === 2) u16(a, b, view(result, n))
    else u32(a, b, view(result, n))

    return result
  }
}

function reduce (u8, u16 = u8, u32 = u16) {
  return function reduce (buf) {
    if (buf.byteLength % 16 !== 0) {
      throw new Error('Buffer length must be a multiple of 16')
    }

    const n = buf.BYTES_PER_ELEMENT

    if (n === 1) return u8(buf)
    if (n === 2) return u16(buf)
    return u32(buf)
  }
}

exports.allo = function allo (buf) {
  if (buf.byteLength % 16 !== 0) {
    throw new Error('Buffer length must be a multiple of 16')
  }

  const m = 2 ** (buf.BYTES_PER_ELEMENT * 8) - 1

  for (let i = 0, n = buf.length; i < n; i++) {
    if (buf[i] !== m) return false
  }

  return true
}

exports.allz = function allz (buf) {
  if (buf.byteLength % 16 !== 0) {
    throw new Error('Buffer length must be a multiple of 16')
  }

  for (let i = 0, n = buf.length; i < n; i++) {
    if (buf[i] !== 0) return false
  }

  return true
}

exports.and = binary(
  (a, b, result) => {
    for (let i = 0, n = result.length; i < n; i++) {
      result[i] = a[i] & b[i]
    }
  }
)

exports.clear = binary(
  (a, b, result) => {
    for (let i = 0, n = result.length; i < n; i++) {
      result[i] = a[i] & ~b[i]
    }
  }
)

exports.clo = unary(
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = 24 - scalar.clo(buf[i])
    }
  },
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = 16 - scalar.clo(buf[i])
    }
  },
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = scalar.clo(buf[i])
    }
  }
)

exports.clz = unary(
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = 24 - scalar.clz(buf[i])
    }
  },
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = 16 - scalar.clz(buf[i])
    }
  },
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = scalar.clz(buf[i])
    }
  }
)

exports.cnt = unary(
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = scalar.cnt(buf[i]) & 0xff
    }
  },
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = scalar.cnt(buf[i]) & 0xffff
    }
  },
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = scalar.cnt(buf[i])
    }
  }
)

exports.cto = unary(
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = Math.min(scalar.cto(buf[i]), 8)
    }
  },
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = Math.min(scalar.cto(buf[i]), 16)
    }
  },
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = scalar.cto(buf[i])
    }
  }
)

exports.ctz = unary(
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = Math.min(scalar.ctz(buf[i]), 8)
    }
  },
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = Math.min(scalar.ctz(buf[i]), 16)
    }
  },
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = scalar.ctz(buf[i])
    }
  }
)

exports.not = unary(
  (buf, result) => {
    for (let i = 0, n = buf.length; i < n; i++) {
      result[i] = ~buf[i]
    }
  }
)

exports.or = binary(
  (a, b, result) => {
    for (let i = 0, n = result.length; i < n; i++) {
      result[i] = a[i] | b[i]
    }
  }
)

exports.sum = reduce(
  (buf) => {
    let result = 0n

    for (let i = 0, n = buf.length; i < n; i++) {
      result += BigInt(buf[i])
    }

    return result
  }
)

exports.xor = binary(
  (a, b, result) => {
    for (let i = 0, n = result.length; i < n; i++) {
      result[i] = a[i] ^ b[i]
    }
  }
)

},{"./scalar":75,"b4a":4}],75:[function(require,module,exports){
const clz = exports.clz = function clz (n) {
  return Math.clz32(n)
}

exports.clo = function clo (n) {
  return clz(~n)
}

const ctz = exports.ctz = function ctz (n) {
  return 32 - (n === 0 ? 0 : (clz(n & -n) + 1))
}

exports.cto = function cto (n) {
  return ctz(~n)
}

exports.cnt = function cnt (n) {
  n = n - ((n >>> 1) & 0x55555555)
  n = (n & 0x33333333) + ((n >>> 2) & 0x33333333)
  n = (n + (n >>> 4)) & 0x0f0f0f0f
  n = (n * 0x01010101) >>> 24
  return n
}

},{}],76:[function(require,module,exports){
module.exports = fallback

function _add (a, b) {
  var rl = a.l + b.l
  var a2 = {
    h: a.h + b.h + (rl / 2 >>> 31) >>> 0,
    l: rl >>> 0
  }
  a.h = a2.h
  a.l = a2.l
}

function _xor (a, b) {
  a.h ^= b.h
  a.h >>>= 0
  a.l ^= b.l
  a.l >>>= 0
}

function _rotl (a, n) {
  var a2 = {
    h: a.h << n | a.l >>> (32 - n),
    l: a.l << n | a.h >>> (32 - n)
  }
  a.h = a2.h
  a.l = a2.l
}

function _rotl32 (a) {
  var al = a.l
  a.l = a.h
  a.h = al
}

function _compress (v0, v1, v2, v3) {
  _add(v0, v1)
  _add(v2, v3)
  _rotl(v1, 13)
  _rotl(v3, 16)
  _xor(v1, v0)
  _xor(v3, v2)
  _rotl32(v0)
  _add(v2, v1)
  _add(v0, v3)
  _rotl(v1, 17)
  _rotl(v3, 21)
  _xor(v1, v2)
  _xor(v3, v0)
  _rotl32(v2)
}

function _get_int (a, offset) {
  return (a[offset + 3] << 24) | (a[offset + 2] << 16) | (a[offset + 1] << 8) | a[offset]
}

function fallback (out, m, key) { // modified from https://github.com/jedisct1/siphash-js to use uint8arrays
  var k0 = {h: _get_int(key, 4), l: _get_int(key, 0)}
  var k1 = {h: _get_int(key, 12), l: _get_int(key, 8)}
  var v0 = {h: k0.h, l: k0.l}
  var v2 = k0
  var v1 = {h: k1.h, l: k1.l}
  var v3 = k1
  var mi
  var mp = 0
  var ml = m.length
  var ml7 = ml - 7
  var buf = new Uint8Array(new ArrayBuffer(8))

  _xor(v0, {h: 0x736f6d65, l: 0x70736575})
  _xor(v1, {h: 0x646f7261, l: 0x6e646f6d})
  _xor(v2, {h: 0x6c796765, l: 0x6e657261})
  _xor(v3, {h: 0x74656462, l: 0x79746573})

  while (mp < ml7) {
    mi = {h: _get_int(m, mp + 4), l: _get_int(m, mp)}
    _xor(v3, mi)
    _compress(v0, v1, v2, v3)
    _compress(v0, v1, v2, v3)
    _xor(v0, mi)
    mp += 8
  }

  buf[7] = ml
  var ic = 0
  while (mp < ml) {
    buf[ic++] = m[mp++]
  }
  while (ic < 7) {
    buf[ic++] = 0
  }

  mi = {
    h: buf[7] << 24 | buf[6] << 16 | buf[5] << 8 | buf[4],
    l: buf[3] << 24 | buf[2] << 16 | buf[1] << 8 | buf[0]
  }

  _xor(v3, mi)
  _compress(v0, v1, v2, v3)
  _compress(v0, v1, v2, v3)
  _xor(v0, mi)
  _xor(v2, { h: 0, l: 0xff })
  _compress(v0, v1, v2, v3)
  _compress(v0, v1, v2, v3)
  _compress(v0, v1, v2, v3)
  _compress(v0, v1, v2, v3)

  var h = v0
  _xor(h, v1)
  _xor(h, v2)
  _xor(h, v3)

  out[0] = h.l & 0xff
  out[1] = (h.l >> 8) & 0xff
  out[2] = (h.l >> 16) & 0xff
  out[3] = (h.l >> 24) & 0xff
  out[4] = h.h & 0xff
  out[5] = (h.h >> 8) & 0xff
  out[6] = (h.h >> 16) & 0xff
  out[7] = (h.h >> 24) & 0xff
}

},{}],77:[function(require,module,exports){
var assert = require('nanoassert')
var wasm = typeof WebAssembly !== 'undefined' && require('./siphash24')()
var fallback = require('./fallback')

module.exports = siphash24

var BYTES = siphash24.BYTES = 8
var KEYBYTES = siphash24.KEYBYTES = 16

siphash24.WASM_SUPPORTED = !!wasm
siphash24.WASM_LOADED = !!wasm

var memory = new Uint8Array(wasm ? wasm.memory.buffer : 0)

function siphash24 (data, key, out, noAssert) {
  if (!out) out = new Uint8Array(8)

  if (noAssert !== true) {
    assert(out.length >= BYTES, 'output must be at least ' + BYTES)
    assert(key.length >= KEYBYTES, 'key must be at least ' + KEYBYTES)
  }

  if (wasm) {
    if (data.length + 24 > memory.length) realloc(data.length + 24)
    memory.set(key, 8)
    memory.set(data, 24)
    wasm.siphash(24, data.length)
    out.set(memory.subarray(0, 8))
  } else {
    fallback(out, data, key)
  }

  return out
}

function realloc (size) {
  wasm.memory.grow(Math.max(0, Math.ceil(Math.abs(size - memory.length) / 65536)))
  memory = new Uint8Array(wasm.memory.buffer)
}

},{"./fallback":76,"./siphash24":78,"nanoassert":51}],78:[function(require,module,exports){
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[Object.keys(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __toBinary = /* @__PURE__ */ (() => {
  var table = new Uint8Array(128);
  for (var i = 0; i < 64; i++)
    table[i < 26 ? i + 65 : i < 52 ? i + 71 : i < 62 ? i - 4 : i * 4 - 205] = i;
  return (base64) => {
    var n = base64.length, bytes2 = new Uint8Array((n - (base64[n - 1] == "=") - (base64[n - 2] == "=")) * 3 / 4 | 0);
    for (var i2 = 0, j = 0; i2 < n; ) {
      var c0 = table[base64.charCodeAt(i2++)], c1 = table[base64.charCodeAt(i2++)];
      var c2 = table[base64.charCodeAt(i2++)], c3 = table[base64.charCodeAt(i2++)];
      bytes2[j++] = c0 << 2 | c1 >> 4;
      bytes2[j++] = c1 << 4 | c2 >> 2;
      bytes2[j++] = c2 << 6 | c3;
    }
    return bytes2;
  };
})();

// wasm-binary:./siphash24.wat
var require_siphash24 = __commonJS({
  "wasm-binary:./siphash24.wat"(exports2, module2) {
    module2.exports = __toBinary("AGFzbQEAAAABBgFgAn9/AAMCAQAFBQEBCpBOBxQCBm1lbW9yeQIAB3NpcGhhc2gAAArdCAHaCAIIfgJ/QvXKzYPXrNu38wAhAkLt3pHzlszct+QAIQNC4eSV89bs2bzsACEEQvPK0cunjNmy9AAhBUEIKQMAIQdBECkDACEIIAGtQjiGIQYgAUEHcSELIAAgAWogC2shCiAFIAiFIQUgBCAHhSEEIAMgCIUhAyACIAeFIQICQANAIAAgCkYNASAAKQMAIQkgBSAJhSEFIAIgA3whAiADQg2JIQMgAyAChSEDIAJCIIkhAiAEIAV8IQQgBUIQiSEFIAUgBIUhBSACIAV8IQIgBUIViSEFIAUgAoUhBSAEIAN8IQQgA0IRiSEDIAMgBIUhAyAEQiCJIQQgAiADfCECIANCDYkhAyADIAKFIQMgAkIgiSECIAQgBXwhBCAFQhCJIQUgBSAEhSEFIAIgBXwhAiAFQhWJIQUgBSAChSEFIAQgA3whBCADQhGJIQMgAyAEhSEDIARCIIkhBCACIAmFIQIgAEEIaiEADAALCwJAAkACQAJAAkACQAJAAkAgCw4HBwYFBAMCAQALIAYgADEABkIwhoQhBgsgBiAAMQAFQiiGhCEGCyAGIAAxAARCIIaEIQYLIAYgADEAA0IYhoQhBgsgBiAAMQACQhCGhCEGCyAGIAAxAAFCCIaEIQYLIAYgADEAAIQhBgsgBSAGhSEFIAIgA3whAiADQg2JIQMgAyAChSEDIAJCIIkhAiAEIAV8IQQgBUIQiSEFIAUgBIUhBSACIAV8IQIgBUIViSEFIAUgAoUhBSAEIAN8IQQgA0IRiSEDIAMgBIUhAyAEQiCJIQQgAiADfCECIANCDYkhAyADIAKFIQMgAkIgiSECIAQgBXwhBCAFQhCJIQUgBSAEhSEFIAIgBXwhAiAFQhWJIQUgBSAChSEFIAQgA3whBCADQhGJIQMgAyAEhSEDIARCIIkhBCACIAaFIQIgBEL/AYUhBCACIAN8IQIgA0INiSEDIAMgAoUhAyACQiCJIQIgBCAFfCEEIAVCEIkhBSAFIASFIQUgAiAFfCECIAVCFYkhBSAFIAKFIQUgBCADfCEEIANCEYkhAyADIASFIQMgBEIgiSEEIAIgA3whAiADQg2JIQMgAyAChSEDIAJCIIkhAiAEIAV8IQQgBUIQiSEFIAUgBIUhBSACIAV8IQIgBUIViSEFIAUgAoUhBSAEIAN8IQQgA0IRiSEDIAMgBIUhAyAEQiCJIQQgAiADfCECIANCDYkhAyADIAKFIQMgAkIgiSECIAQgBXwhBCAFQhCJIQUgBSAEhSEFIAIgBXwhAiAFQhWJIQUgBSAChSEFIAQgA3whBCADQhGJIQMgAyAEhSEDIARCIIkhBCACIAN8IQIgA0INiSEDIAMgAoUhAyACQiCJIQIgBCAFfCEEIAVCEIkhBSAFIASFIQUgAiAFfCECIAVCFYkhBSAFIAKFIQUgBCADfCEEIANCEYkhAyADIASFIQMgBEIgiSEEQQAgAiADIAQgBYWFhTcDAAs=");
  }
});

// wasm-module:./siphash24.wat
var bytes = require_siphash24();
var compiled = new WebAssembly.Module(bytes);
module.exports = (imports) => {
  const instance = new WebAssembly.Instance(compiled, imports);
  return instance.exports;
};

},{}],79:[function(require,module,exports){
/* eslint-disable camelcase */
const { crypto_stream_chacha20_ietf, crypto_stream_chacha20_ietf_xor_ic } = require('./crypto_stream_chacha20')
const { crypto_verify_16 } = require('./crypto_verify')
const Poly1305 = require('./internal/poly1305')
const assert = require('nanoassert')

const crypto_aead_chacha20poly1305_ietf_KEYBYTES = 32
const crypto_aead_chacha20poly1305_ietf_NSECBYTES = 0
const crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12
const crypto_aead_chacha20poly1305_ietf_ABYTES = 16
const crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER

const _pad0 = new Uint8Array(16)

function crypto_aead_chacha20poly1305_ietf_encrypt (c, m, ad, nsec, npub, k) {
  if (ad === null) return crypto_aead_chacha20poly1305_ietf_encrypt(c, m, new Uint8Array(0), nsec, npub, k)

  assert(c.byteLength === m.byteLength + crypto_aead_chacha20poly1305_ietf_ABYTES,
    "ciphertext should be 'crypto_aead_chacha20poly1305_ietf_ABYTES' longer than message")
  assert(npub.byteLength === crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
    "npub should be 'crypto_aead_chacha20poly1305_ietf_NPUBBYTES' long")
  assert(k.byteLength === crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    "k should be 'crypto_aead_chacha20poly1305_ietf_KEYBYTES' long")
  assert(m.byteLength <= crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX, 'message is too large')

  const ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached(c.subarray(0, m.byteLength),
    c.subarray(m.byteLength), m, ad, nsec, npub, k)

  return m.byteLength + ret
}

function crypto_aead_chacha20poly1305_ietf_encrypt_detached (c, mac, m, ad, nsec, npub, k) {
  if (ad === null) return crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, m, new Uint8Array(0), nsec, npub, k)

  assert(c.byteLength === m.byteLength, 'ciphertext should be same length than message')
  assert(npub.byteLength === crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
    "npub should be 'crypto_aead_chacha20poly1305_ietf_NPUBBYTES' long")
  assert(k.byteLength === crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    "k should be 'crypto_aead_chacha20poly1305_ietf_KEYBYTES' long")
  assert(m.byteLength <= crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX, 'message is too large')
  assert(mac.byteLength <= crypto_aead_chacha20poly1305_ietf_ABYTES,
    "mac should be 'crypto_aead_chacha20poly1305_ietf_ABYTES' long")

  const block0 = new Uint8Array(64)
  var slen = new Uint8Array(8)

  crypto_stream_chacha20_ietf(block0, npub, k)
  const poly = new Poly1305(block0)
  block0.fill(0)

  poly.update(ad, 0, ad.byteLength)
  poly.update(_pad0, 0, (0x10 - ad.byteLength) & 0xf)

  crypto_stream_chacha20_ietf_xor_ic(c, m, npub, 1, k)

  poly.update(c, 0, m.byteLength)
  poly.update(_pad0, 0, (0x10 - m.byteLength) & 0xf)

  write64LE(slen, 0, ad.byteLength)
  poly.update(slen, 0, slen.byteLength)

  write64LE(slen, 0, m.byteLength)
  poly.update(slen, 0, slen.byteLength)

  poly.finish(mac, 0)
  slen.fill(0)

  return crypto_aead_chacha20poly1305_ietf_ABYTES
}

function crypto_aead_chacha20poly1305_ietf_decrypt (m, nsec, c, ad, npub, k) {
  if (ad === null) return crypto_aead_chacha20poly1305_ietf_decrypt(m, nsec, c, new Uint8Array(0), npub, k)

  assert(m.byteLength === c.byteLength - crypto_aead_chacha20poly1305_ietf_ABYTES,
    "message should be 'crypto_aead_chacha20poly1305_ietf_ABYTES' shorter than ciphertext")
  assert(npub.byteLength === crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
    "npub should be 'crypto_aead_chacha20poly1305_ietf_NPUBBYTES' long")
  assert(k.byteLength === crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    "k should be 'crypto_aead_chacha20poly1305_ietf_KEYBYTES' long")
  assert(m.byteLength <= crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX, 'message is too large')

  if (c.byteLength < crypto_aead_chacha20poly1305_ietf_ABYTES) throw new Error('could not verify data')

  crypto_aead_chacha20poly1305_ietf_decrypt_detached(
    m, nsec,
    c.subarray(0, c.byteLength - crypto_aead_chacha20poly1305_ietf_ABYTES),
    c.subarray(c.byteLength - crypto_aead_chacha20poly1305_ietf_ABYTES),
    ad, npub, k)

  return c.byteLength - crypto_aead_chacha20poly1305_ietf_ABYTES
}

function crypto_aead_chacha20poly1305_ietf_decrypt_detached (m, nsec, c, mac, ad, npub, k) {
  if (ad === null) return crypto_aead_chacha20poly1305_ietf_decrypt_detached(m, nsec, c, mac, new Uint8Array(0), npub, k)

  assert(c.byteLength === m.byteLength, 'message should be same length than ciphertext')
  assert(npub.byteLength === crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
    "npub should be 'crypto_aead_chacha20poly1305_ietf_NPUBBYTES' long")
  assert(k.byteLength === crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    "k should be 'crypto_aead_chacha20poly1305_ietf_KEYBYTES' long")
  assert(m.byteLength <= crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX, 'message is too large')
  assert(mac.byteLength <= crypto_aead_chacha20poly1305_ietf_ABYTES,
    "mac should be 'crypto_aead_chacha20poly1305_ietf_ABYTES' long")

  const block0 = new Uint8Array(64)
  const slen = new Uint8Array(8)
  const computed_mac = new Uint8Array(crypto_aead_chacha20poly1305_ietf_ABYTES)

  crypto_stream_chacha20_ietf(block0, npub, k)
  const poly = new Poly1305(block0)
  block0.fill(0)

  poly.update(ad, 0, ad.byteLength)
  poly.update(_pad0, 0, (0x10 - ad.byteLength) & 0xf)

  const mlen = c.byteLength
  poly.update(c, 0, mlen)
  poly.update(_pad0, 0, (0x10 - mlen) & 0xf)

  write64LE(slen, 0, ad.byteLength)
  poly.update(slen, 0, slen.byteLength)

  write64LE(slen, 0, mlen)
  poly.update(slen, 0, slen.byteLength)

  poly.finish(computed_mac, 0)

  assert(computed_mac.byteLength === 16)
  const ret = crypto_verify_16(computed_mac, 0, mac, 0)

  computed_mac.fill(0)
  slen.fill(0)

  if (!ret) {
    m.fill(0)
    throw new Error('could not verify data')
  }

  crypto_stream_chacha20_ietf_xor_ic(m, c, npub, 1, k)
}

function write64LE (buf, offset, int) {
  buf.fill(0, 0, 8)

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  view.setUint32(offset, int & 0xffffffff, true)
  view.setUint32(offset + 4, (int / 2 ** 32) & 0xffffffff, true)
}

module.exports = {
  crypto_aead_chacha20poly1305_ietf_encrypt,
  crypto_aead_chacha20poly1305_ietf_encrypt_detached,
  crypto_aead_chacha20poly1305_ietf_decrypt,
  crypto_aead_chacha20poly1305_ietf_decrypt_detached,
  crypto_aead_chacha20poly1305_ietf_ABYTES,
  crypto_aead_chacha20poly1305_ietf_KEYBYTES,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_aead_chacha20poly1305_ietf_NSECBYTES,
  crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX
}

},{"./crypto_stream_chacha20":94,"./crypto_verify":95,"./internal/poly1305":100,"nanoassert":51}],80:[function(require,module,exports){
/* eslint-disable camelcase */
const { crypto_verify_32 } = require('./crypto_verify')
const Sha512 = require('sha512-universal')
const assert = require('nanoassert')

const crypto_auth_BYTES = 32
const crypto_auth_KEYBYTES = 32

function crypto_auth (out, input, k) {
  assert(out.byteLength === crypto_auth_BYTES, "out should be 'crypto_auth_BYTES' in length")
  assert(k.byteLength === crypto_auth_KEYBYTES, "key should be 'crypto_auth_KEYBYTES' in length")

  const out0 = new Uint8Array(64)
  const hmac = Sha512.HMAC(k)
  hmac.update(input)
  hmac.digest(out0)

  out.set(out0.subarray(0, 32))
}

function crypto_auth_verify (h, input, k) {
  assert(h.byteLength === crypto_auth_BYTES, "h should be 'crypto_auth_BYTES' in length")
  assert(k.byteLength === crypto_auth_KEYBYTES, "key should be 'crypto_auth_KEYBYTES' in length")

  const correct = Sha512.HMAC(k).update(input).digest()

  return crypto_verify_32(h, 0, correct, 0)
}

module.exports = {
  crypto_auth_BYTES,
  crypto_auth_KEYBYTES,
  crypto_auth,
  crypto_auth_verify
}

},{"./crypto_verify":95,"nanoassert":51,"sha512-universal":70}],81:[function(require,module,exports){
/* eslint-disable camelcase */
const { crypto_hash_sha512 } = require('./crypto_hash')
const { crypto_scalarmult, crypto_scalarmult_base } = require('./crypto_scalarmult')
const { randombytes } = require('./randombytes')
const { crypto_generichash_batch } = require('./crypto_generichash')
const { crypto_stream_xsalsa20_MESSAGEBYTES_MAX } = require('./crypto_stream')
const {
  crypto_secretbox_open_easy,
  crypto_secretbox_easy,
  crypto_secretbox_detached,
  crypto_secretbox_open_detached
} = require('./crypto_secretbox')
const xsalsa20 = require('xsalsa20')
const assert = require('nanoassert')

const crypto_box_PUBLICKEYBYTES = 32
const crypto_box_SECRETKEYBYTES = 32
const crypto_box_NONCEBYTES = 24
const crypto_box_ZEROBYTES = 32
const crypto_box_BOXZEROBYTES = 16
const crypto_box_SEALBYTES = 48
const crypto_box_SEEDBYTES = 32
const crypto_box_BEFORENMBYTES = 32
const crypto_box_MACBYTES = 16

const crypto_box_curve25519xsalsa20poly1305_MACBYTES = 16

const crypto_box_MESSAGEBYTES_MAX =
  crypto_stream_xsalsa20_MESSAGEBYTES_MAX -
  crypto_box_curve25519xsalsa20poly1305_MACBYTES

module.exports = {
  crypto_box_easy,
  crypto_box_open_easy,
  crypto_box_keypair,
  crypto_box_seed_keypair,
  crypto_box_seal,
  crypto_box_seal_open,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_box_NONCEBYTES,
  crypto_box_ZEROBYTES,
  crypto_box_BOXZEROBYTES,
  crypto_box_SEALBYTES,
  crypto_box_SEEDBYTES,
  crypto_box_BEFORENMBYTES,
  crypto_box_MACBYTES
}

function crypto_box_keypair (pk, sk) {
  check(pk, crypto_box_PUBLICKEYBYTES)
  check(sk, crypto_box_SECRETKEYBYTES)
  randombytes(sk, 32)
  return crypto_scalarmult_base(pk, sk)
}
function crypto_box_seed_keypair (pk, sk, seed) {
  assert(pk.byteLength === crypto_box_PUBLICKEYBYTES, "pk should be 'crypto_box_PUBLICKEYBYTES' bytes")
  assert(sk.byteLength === crypto_box_SECRETKEYBYTES, "sk should be 'crypto_box_SECRETKEYBYTES' bytes")
  assert(sk.byteLength === crypto_box_SEEDBYTES, "sk should be 'crypto_box_SEEDBYTES' bytes")

  const hash = new Uint8Array(64)
  crypto_hash_sha512(hash, seed, 32)
  sk.set(hash.subarray(0, 32))
  hash.fill(0)

  return crypto_scalarmult_base(pk, sk)
}

function crypto_box_seal (c, m, pk) {
  check(c, crypto_box_SEALBYTES + m.length)
  check(pk, crypto_box_PUBLICKEYBYTES)

  var epk = c.subarray(0, crypto_box_PUBLICKEYBYTES)
  var esk = new Uint8Array(crypto_box_SECRETKEYBYTES)
  crypto_box_keypair(epk, esk)

  var n = new Uint8Array(crypto_box_NONCEBYTES)
  crypto_generichash_batch(n, [epk, pk])

  var s = new Uint8Array(crypto_box_PUBLICKEYBYTES)
  crypto_scalarmult(s, esk, pk)

  var k = new Uint8Array(crypto_box_BEFORENMBYTES)
  var zero = new Uint8Array(16)
  xsalsa20.core_hsalsa20(k, zero, s, xsalsa20.SIGMA)

  crypto_secretbox_easy(c.subarray(epk.length), m, n, k)

  cleanup(esk)
}

function crypto_box_seal_open (m, c, pk, sk) {
  check(c, crypto_box_SEALBYTES)
  check(m, c.length - crypto_box_SEALBYTES)
  check(pk, crypto_box_PUBLICKEYBYTES)
  check(sk, crypto_box_SECRETKEYBYTES)

  var epk = c.subarray(0, crypto_box_PUBLICKEYBYTES)

  var n = new Uint8Array(crypto_box_NONCEBYTES)
  crypto_generichash_batch(n, [epk, pk])

  var s = new Uint8Array(crypto_box_PUBLICKEYBYTES)
  crypto_scalarmult(s, sk, epk)

  var k = new Uint8Array(crypto_box_BEFORENMBYTES)
  var zero = new Uint8Array(16)
  xsalsa20.core_hsalsa20(k, zero, s, xsalsa20.SIGMA)

  return crypto_secretbox_open_easy(m, c.subarray(epk.length), n, k)
}

function crypto_box_beforenm (k, pk, sk) {
  const zero = new Uint8Array(16)
  const s = new Uint8Array(32)

  assert(crypto_scalarmult(s, sk, pk) === 0)

  xsalsa20.core_hsalsa20(k, zero, s, xsalsa20.SIGMA)

  return true
}

function crypto_box_detached_afternm (c, mac, m, n, k) {
  return crypto_secretbox_detached(c, mac, m, n, k)
}

function crypto_box_detached (c, mac, m, n, pk, sk) {
  check(mac, crypto_box_MACBYTES)
  check(n, crypto_box_NONCEBYTES)
  check(pk, crypto_box_PUBLICKEYBYTES)
  check(sk, crypto_box_SECRETKEYBYTES)

  const k = new Uint8Array(crypto_box_BEFORENMBYTES)

  assert(crypto_box_beforenm(k, pk, sk))

  const ret = crypto_box_detached_afternm(c, mac, m, n, k)
  cleanup(k)

  return ret
}

function crypto_box_easy (c, m, n, pk, sk) {
  assert(
    c.length >= m.length + crypto_box_MACBYTES,
    "c should be at least 'm.length + crypto_box_MACBYTES' bytes"
  )
  assert(
    m.length <= crypto_box_MESSAGEBYTES_MAX,
    "m should be at most 'crypto_box_MESSAGEBYTES_MAX' bytes"
  )

  return crypto_box_detached(
    c.subarray(crypto_box_MACBYTES, m.length + crypto_box_MACBYTES),
    c.subarray(0, crypto_box_MACBYTES),
    m,
    n,
    pk,
    sk
  )
}

function crypto_box_open_detached_afternm (m, c, mac, n, k) {
  return crypto_secretbox_open_detached(m, c, mac, n, k)
}

function crypto_box_open_detached (m, c, mac, n, pk, sk) {
  const k = new Uint8Array(crypto_box_BEFORENMBYTES)
  assert(crypto_box_beforenm(k, pk, sk))

  const ret = crypto_box_open_detached_afternm(m, c, mac, n, k)
  cleanup(k)

  return ret
}

function crypto_box_open_easy (m, c, n, pk, sk) {
  assert(
    c.length >= m.length + crypto_box_MACBYTES,
    "c should be at least 'm.length + crypto_box_MACBYTES' bytes"
  )

  return crypto_box_open_detached(
    m,
    c.subarray(crypto_box_MACBYTES, m.length + crypto_box_MACBYTES),
    c.subarray(0, crypto_box_MACBYTES),
    n,
    pk,
    sk
  )
}

function check (buf, len) {
  if (!buf || (len && buf.length < len)) throw new Error('Argument must be a buffer' + (len ? ' of length ' + len : ''))
}

function cleanup (arr) {
  for (let i = 0; i < arr.length; i++) arr[i] = 0
}

},{"./crypto_generichash":82,"./crypto_hash":83,"./crypto_scalarmult":88,"./crypto_secretbox":89,"./crypto_stream":93,"./randombytes":102,"nanoassert":51,"xsalsa20":131}],82:[function(require,module,exports){
var blake2b = require('blake2b')

if (new Uint16Array([1])[0] !== 1) throw new Error('Big endian architecture is not supported.')

module.exports.crypto_generichash_PRIMITIVE = 'blake2b'
module.exports.crypto_generichash_BYTES_MIN = blake2b.BYTES_MIN
module.exports.crypto_generichash_BYTES_MAX = blake2b.BYTES_MAX
module.exports.crypto_generichash_BYTES = blake2b.BYTES
module.exports.crypto_generichash_KEYBYTES_MIN = blake2b.KEYBYTES_MIN
module.exports.crypto_generichash_KEYBYTES_MAX = blake2b.KEYBYTES_MAX
module.exports.crypto_generichash_KEYBYTES = blake2b.KEYBYTES
module.exports.crypto_generichash_WASM_SUPPORTED = blake2b.WASM_SUPPORTED
module.exports.crypto_generichash_WASM_LOADED = false

module.exports.crypto_generichash = function (output, input, key) {
  blake2b(output.length, key).update(input).final(output)
}

module.exports.crypto_generichash_ready = blake2b.ready

module.exports.crypto_generichash_batch = function (output, inputArray, key) {
  var ctx = blake2b(output.length, key)
  for (var i = 0; i < inputArray.length; i++) {
    ctx.update(inputArray[i])
  }
  ctx.final(output)
}

module.exports.crypto_generichash_instance = function (key, outlen) {
  if (outlen == null) outlen = module.exports.crypto_generichash_BYTES
  return blake2b(outlen, key)
}

blake2b.ready(function (_) {
  module.exports.crypto_generichash_WASM_LOADED = blake2b.WASM_LOADED
})

},{"blake2b":13}],83:[function(require,module,exports){
/* eslint-disable camelcase */
const sha512 = require('sha512-universal')
const assert = require('nanoassert')

if (new Uint16Array([1])[0] !== 1) throw new Error('Big endian architecture is not supported.')

const crypto_hash_sha512_BYTES = 64
const crypto_hash_BYTES = crypto_hash_sha512_BYTES

function crypto_hash_sha512 (out, m, n) {
  assert(out.byteLength === crypto_hash_sha512_BYTES, "out must be 'crypto_hash_sha512_BYTES' bytes long")

  sha512().update(m.subarray(0, n)).digest(out)
  return 0
}

function crypto_hash (out, m, n) {
  return crypto_hash_sha512(out, m, n)
}

module.exports = {
  crypto_hash,
  crypto_hash_sha512,
  crypto_hash_sha512_BYTES,
  crypto_hash_BYTES
}

},{"nanoassert":51,"sha512-universal":70}],84:[function(require,module,exports){
/* eslint-disable camelcase */
const sha256 = require('sha256-universal')
const assert = require('nanoassert')

if (new Uint16Array([1])[0] !== 1) throw new Error('Big endian architecture is not supported.')

const crypto_hash_sha256_BYTES = 32

function crypto_hash_sha256 (out, m, n) {
  assert(out.byteLength === crypto_hash_sha256_BYTES, "out must be 'crypto_hash_sha256_BYTES' bytes long")

  sha256().update(m.subarray(0, n)).digest(out)
  return 0
}

module.exports = {
  crypto_hash_sha256,
  crypto_hash_sha256_BYTES
}

},{"nanoassert":51,"sha256-universal":66}],85:[function(require,module,exports){
/* eslint-disable camelcase */
const assert = require('nanoassert')
const randombytes_buf = require('./randombytes').randombytes_buf
const blake2b = require('blake2b')

module.exports.crypto_kdf_PRIMITIVE = 'blake2b'
module.exports.crypto_kdf_BYTES_MIN = 16
module.exports.crypto_kdf_BYTES_MAX = 64
module.exports.crypto_kdf_CONTEXTBYTES = 8
module.exports.crypto_kdf_KEYBYTES = 32

function STORE64_LE (dest, int) {
  var mul = 1
  var i = 0
  dest[0] = int & 0xFF
  while (++i < 8 && (mul *= 0x100)) {
    dest[i] = (int / mul) & 0xFF
  }
}

module.exports.crypto_kdf_derive_from_key = function crypto_kdf_derive_from_key (subkey, subkey_id, ctx, key) {
  assert(subkey.length >= module.exports.crypto_kdf_BYTES_MIN, 'subkey must be at least crypto_kdf_BYTES_MIN')
  assert(subkey_id >= 0 && subkey_id <= 0x1fffffffffffff, 'subkey_id must be safe integer')
  assert(ctx.length >= module.exports.crypto_kdf_CONTEXTBYTES, 'context must be at least crypto_kdf_CONTEXTBYTES')

  var ctx_padded = new Uint8Array(blake2b.PERSONALBYTES)
  var salt = new Uint8Array(blake2b.SALTBYTES)

  ctx_padded.set(ctx, 0, module.exports.crypto_kdf_CONTEXTBYTES)
  STORE64_LE(salt, subkey_id)

  var outlen = Math.min(subkey.length, module.exports.crypto_kdf_BYTES_MAX)
  blake2b(outlen, key.subarray(0, module.exports.crypto_kdf_KEYBYTES), salt, ctx_padded, true)
    .final(subkey)
}

module.exports.crypto_kdf_keygen = function crypto_kdf_keygen (out) {
  assert(out.length >= module.exports.crypto_kdf_KEYBYTES, 'out.length must be crypto_kdf_KEYBYTES')
  randombytes_buf(out.subarray(0, module.exports.crypto_kdf_KEYBYTES))
}

},{"./randombytes":102,"blake2b":13,"nanoassert":51}],86:[function(require,module,exports){
/* eslint-disable camelcase */
const { crypto_scalarmult_base } = require('./crypto_scalarmult')
const { crypto_generichash } = require('./crypto_generichash')
const { randombytes_buf } = require('./randombytes')
const assert = require('nanoassert')

const crypto_kx_SEEDBYTES = 32
const crypto_kx_PUBLICKEYBYTES = 32
const crypto_kx_SECRETKEYBYTES = 32

function crypto_kx_keypair (pk, sk) {
  assert(pk.byteLength === crypto_kx_PUBLICKEYBYTES, "pk must be 'crypto_kx_PUBLICKEYBYTES' bytes")
  assert(sk.byteLength === crypto_kx_SECRETKEYBYTES, "sk must be 'crypto_kx_SECRETKEYBYTES' bytes")

  randombytes_buf(sk, crypto_kx_SECRETKEYBYTES)
  return crypto_scalarmult_base(pk, sk)
}

function crypto_kx_seed_keypair (pk, sk, seed) {
  assert(pk.byteLength === crypto_kx_PUBLICKEYBYTES, "pk must be 'crypto_kx_PUBLICKEYBYTES' bytes")
  assert(sk.byteLength === crypto_kx_SECRETKEYBYTES, "sk must be 'crypto_kx_SECRETKEYBYTES' bytes")
  assert(seed.byteLength === crypto_kx_SEEDBYTES, "seed must be 'crypto_kx_SEEDBYTES' bytes")

  crypto_generichash(sk, seed)
  return crypto_scalarmult_base(pk, sk)
}

module.exports = {
  crypto_kx_keypair,
  crypto_kx_seed_keypair,
  crypto_kx_SEEDBYTES,
  crypto_kx_SECRETKEYBYTES,
  crypto_kx_PUBLICKEYBYTES
}

},{"./crypto_generichash":82,"./crypto_scalarmult":88,"./randombytes":102,"nanoassert":51}],87:[function(require,module,exports){
/* eslint-disable camelcase */
const assert = require('nanoassert')
const Poly1305 = require('./internal/poly1305')
const { crypto_verify_16 } = require('./crypto_verify')

const crypto_onetimeauth_BYTES = 16
const crypto_onetimeauth_KEYBYTES = 32
const crypto_onetimeauth_PRIMITIVE = 'poly1305'

module.exports = {
  crypto_onetimeauth,
  crypto_onetimeauth_verify,
  crypto_onetimeauth_BYTES,
  crypto_onetimeauth_KEYBYTES,
  crypto_onetimeauth_PRIMITIVE
}

function crypto_onetimeauth (mac, msg, key) {
  assert(mac.byteLength === crypto_onetimeauth_BYTES, "mac must be 'crypto_onetimeauth_BYTES' bytes")
  assert(msg.byteLength != null, 'msg must be buffer')
  assert(key.byteLength === crypto_onetimeauth_KEYBYTES, "key must be 'crypto_onetimeauth_KEYBYTES' bytes")

  var s = new Poly1305(key)
  s.update(msg, 0, msg.byteLength)
  s.finish(mac, 0)
}

function crypto_onetimeauth_verify (mac, msg, key) {
  assert(mac.byteLength === crypto_onetimeauth_BYTES, "mac must be 'crypto_onetimeauth_BYTES' bytes")
  assert(msg.byteLength != null, 'msg must be buffer')
  assert(key.byteLength === crypto_onetimeauth_KEYBYTES, "key must be 'crypto_onetimeauth_KEYBYTES' bytes")

  var tmp = new Uint8Array(16)
  crypto_onetimeauth(tmp, msg, key)
  return crypto_verify_16(mac, 0, tmp, 0)
}

},{"./crypto_verify":95,"./internal/poly1305":100,"nanoassert":51}],88:[function(require,module,exports){
/* eslint-disable camelcase, one-var */
const { _9, _121665, gf, inv25519, pack25519, unpack25519, sel25519, A, M, Z, S } = require('./internal/ed25519')

const crypto_scalarmult_BYTES = 32
const crypto_scalarmult_SCALARBYTES = 32

module.exports = {
  crypto_scalarmult,
  crypto_scalarmult_base,
  crypto_scalarmult_BYTES,
  crypto_scalarmult_SCALARBYTES
}

function crypto_scalarmult (q, n, p) {
  check(q, crypto_scalarmult_BYTES)
  check(n, crypto_scalarmult_SCALARBYTES)
  check(p, crypto_scalarmult_BYTES)
  var z = new Uint8Array(32)
  var x = new Float64Array(80), r, i
  var a = gf(), b = gf(), c = gf(),
    d = gf(), e = gf(), f = gf()
  for (i = 0; i < 31; i++) z[i] = n[i]
  z[31] = (n[31] & 127) | 64
  z[0] &= 248
  unpack25519(x, p)
  for (i = 0; i < 16; i++) {
    b[i] = x[i]
    d[i] = a[i] = c[i] = 0
  }
  a[0] = d[0] = 1
  for (i = 254; i >= 0; --i) {
    r = (z[i >>> 3] >>> (i & 7)) & 1
    sel25519(a, b, r)
    sel25519(c, d, r)
    A(e, a, c)
    Z(a, a, c)
    A(c, b, d)
    Z(b, b, d)
    S(d, e)
    S(f, a)
    M(a, c, a)
    M(c, b, e)
    A(e, a, c)
    Z(a, a, c)
    S(b, a)
    Z(c, d, f)
    M(a, c, _121665)
    A(a, a, d)
    M(c, c, a)
    M(a, d, f)
    M(d, b, x)
    S(b, e)
    sel25519(a, b, r)
    sel25519(c, d, r)
  }
  for (i = 0; i < 16; i++) {
    x[i + 16] = a[i]
    x[i + 32] = c[i]
    x[i + 48] = b[i]
    x[i + 64] = d[i]
  }
  var x32 = x.subarray(32)
  var x16 = x.subarray(16)
  inv25519(x32, x32)
  M(x16, x16, x32)
  pack25519(q, x16)
  return 0
}

function crypto_scalarmult_base (q, n) {
  return crypto_scalarmult(q, n, _9)
}

function check (buf, len) {
  if (!buf || (len && buf.length < len)) throw new Error('Argument must be a buffer' + (len ? ' of length ' + len : ''))
}

},{"./internal/ed25519":98}],89:[function(require,module,exports){
/* eslint-disable camelcase */
const assert = require('nanoassert')
const { crypto_stream, crypto_stream_xor } = require('./crypto_stream')
const { crypto_onetimeauth, crypto_onetimeauth_verify, crypto_onetimeauth_BYTES, crypto_onetimeauth_KEYBYTES } = require('./crypto_onetimeauth')

const crypto_secretbox_KEYBYTES = 32
const crypto_secretbox_NONCEBYTES = 24
const crypto_secretbox_ZEROBYTES = 32
const crypto_secretbox_BOXZEROBYTES = 16
const crypto_secretbox_MACBYTES = 16

module.exports = {
  crypto_secretbox,
  crypto_secretbox_open,
  crypto_secretbox_detached,
  crypto_secretbox_open_detached,
  crypto_secretbox_easy,
  crypto_secretbox_open_easy,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_ZEROBYTES,
  crypto_secretbox_BOXZEROBYTES,
  crypto_secretbox_MACBYTES
}

function crypto_secretbox (c, m, n, k) {
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  const mlen = m.byteLength
  assert(mlen >= crypto_secretbox_ZEROBYTES, "mlen must be at least 'crypto_secretbox_ZEROBYTES'")
  assert(n.byteLength === crypto_secretbox_NONCEBYTES, "n must be 'crypto_secretbox_NONCEBYTES' bytes")
  assert(k.byteLength === crypto_secretbox_KEYBYTES, "k must be 'crypto_secretbox_KEYBYTES' bytes")

  crypto_stream_xor(c, m, n, k)
  crypto_onetimeauth(
    c.subarray(crypto_secretbox_BOXZEROBYTES, crypto_secretbox_BOXZEROBYTES + crypto_onetimeauth_BYTES),
    c.subarray(crypto_secretbox_BOXZEROBYTES + crypto_onetimeauth_BYTES, c.byteLength),
    c.subarray(0, crypto_onetimeauth_KEYBYTES)
  )
  c.fill(0, 0, crypto_secretbox_BOXZEROBYTES)
}

function crypto_secretbox_open (m, c, n, k) {
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  const mlen = m.byteLength
  assert(mlen >= crypto_secretbox_ZEROBYTES, "mlen must be at least 'crypto_secretbox_ZEROBYTES'")
  assert(n.byteLength === crypto_secretbox_NONCEBYTES, "n must be 'crypto_secretbox_NONCEBYTES' bytes")
  assert(k.byteLength === crypto_secretbox_KEYBYTES, "k must be 'crypto_secretbox_KEYBYTES' bytes")

  const x = new Uint8Array(crypto_onetimeauth_KEYBYTES)
  crypto_stream(x, n, k)
  const validMac = crypto_onetimeauth_verify(
    c.subarray(crypto_secretbox_BOXZEROBYTES, crypto_secretbox_BOXZEROBYTES + crypto_onetimeauth_BYTES),
    c.subarray(crypto_secretbox_BOXZEROBYTES + crypto_onetimeauth_BYTES, c.byteLength),
    x
  )

  if (validMac === false) return false
  crypto_stream_xor(m, c, n, k)
  m.fill(0, 0, 32)
  return true
}

function crypto_secretbox_detached (o, mac, msg, n, k) {
  assert(o.byteLength === msg.byteLength, "o must be 'msg.byteLength' bytes")
  assert(mac.byteLength === crypto_secretbox_MACBYTES, "mac must be 'crypto_secretbox_MACBYTES' bytes")
  assert(n.byteLength === crypto_secretbox_NONCEBYTES, "n must be 'crypto_secretbox_NONCEBYTES' bytes")
  assert(k.byteLength === crypto_secretbox_KEYBYTES, "k must be 'crypto_secretbox_KEYBYTES' bytes")

  const tmp = new Uint8Array(msg.byteLength + mac.byteLength)
  crypto_secretbox_easy(tmp, msg, n, k)
  mac.set(tmp.subarray(0, mac.byteLength))
  o.set(tmp.subarray(mac.byteLength))
  return true
}

function crypto_secretbox_open_detached (msg, o, mac, n, k) {
  assert(o.byteLength === msg.byteLength, "o must be 'msg.byteLength' bytes")
  assert(mac.byteLength === crypto_secretbox_MACBYTES, "mac must be 'crypto_secretbox_MACBYTES' bytes")
  assert(n.byteLength === crypto_secretbox_NONCEBYTES, "n must be 'crypto_secretbox_NONCEBYTES' bytes")
  assert(k.byteLength === crypto_secretbox_KEYBYTES, "k must be 'crypto_secretbox_KEYBYTES' bytes")

  const tmp = new Uint8Array(o.byteLength + mac.byteLength)
  tmp.set(mac)
  tmp.set(o, mac.byteLength)
  return crypto_secretbox_open_easy(msg, tmp, n, k)
}

function crypto_secretbox_easy (o, msg, n, k) {
  assert(o.byteLength === msg.byteLength + crypto_secretbox_MACBYTES, "o must be 'msg.byteLength + crypto_secretbox_MACBYTES' bytes")
  assert(n.byteLength === crypto_secretbox_NONCEBYTES, "n must be 'crypto_secretbox_NONCEBYTES' bytes")
  assert(k.byteLength === crypto_secretbox_KEYBYTES, "k must be 'crypto_secretbox_KEYBYTES' bytes")

  const m = new Uint8Array(crypto_secretbox_ZEROBYTES + msg.byteLength)
  const c = new Uint8Array(m.byteLength)
  m.set(msg, crypto_secretbox_ZEROBYTES)
  crypto_secretbox(c, m, n, k)
  o.set(c.subarray(crypto_secretbox_BOXZEROBYTES))
}

function crypto_secretbox_open_easy (msg, box, n, k) {
  assert(box.byteLength === msg.byteLength + crypto_secretbox_MACBYTES, "box must be 'msg.byteLength + crypto_secretbox_MACBYTES' bytes")
  assert(n.byteLength === crypto_secretbox_NONCEBYTES, "n must be 'crypto_secretbox_NONCEBYTES' bytes")
  assert(k.byteLength === crypto_secretbox_KEYBYTES, "k must be 'crypto_secretbox_KEYBYTES' bytes")

  const c = new Uint8Array(crypto_secretbox_BOXZEROBYTES + box.byteLength)
  const m = new Uint8Array(c.byteLength)
  c.set(box, crypto_secretbox_BOXZEROBYTES)
  if (crypto_secretbox_open(m, c, n, k) === false) return false
  msg.set(m.subarray(crypto_secretbox_ZEROBYTES))
  return true
}

},{"./crypto_onetimeauth":87,"./crypto_stream":93,"nanoassert":51}],90:[function(require,module,exports){
/* eslint-disable camelcase */
const assert = require('nanoassert')
const { randombytes_buf } = require('./randombytes')
const {
  crypto_stream_chacha20_ietf,
  crypto_stream_chacha20_ietf_xor,
  crypto_stream_chacha20_ietf_xor_ic,
  crypto_stream_chacha20_ietf_KEYBYTES
} = require('./crypto_stream_chacha20')
const { crypto_core_hchacha20, crypto_core_hchacha20_INPUTBYTES } = require('./internal/hchacha20')
const Poly1305 = require('./internal/poly1305')
const { sodium_increment, sodium_is_zero, sodium_memcmp } = require('./helpers')

const crypto_onetimeauth_poly1305_BYTES = 16
const crypto_secretstream_xchacha20poly1305_COUNTERBYTES = 4
const crypto_secretstream_xchacha20poly1305_INONCEBYTES = 8
const crypto_aead_xchacha20poly1305_ietf_KEYBYTES = 32
const crypto_secretstream_xchacha20poly1305_KEYBYTES = crypto_aead_xchacha20poly1305_ietf_KEYBYTES
const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24
const crypto_secretstream_xchacha20poly1305_HEADERBYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
const crypto_aead_xchacha20poly1305_ietf_ABYTES = 16
const crypto_secretstream_xchacha20poly1305_ABYTES = 1 + crypto_aead_xchacha20poly1305_ietf_ABYTES
const crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER
const crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER
const crypto_secretstream_xchacha20poly1305_TAGBYTES = 1
const crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = new Uint8Array([0])
const crypto_secretstream_xchacha20poly1305_TAG_PUSH = new Uint8Array([1])
const crypto_secretstream_xchacha20poly1305_TAG_REKEY = new Uint8Array([2])
const crypto_secretstream_xchacha20poly1305_TAG_FINAL = new Uint8Array([crypto_secretstream_xchacha20poly1305_TAG_PUSH | crypto_secretstream_xchacha20poly1305_TAG_REKEY])
const crypto_secretstream_xchacha20poly1305_STATEBYTES = crypto_secretstream_xchacha20poly1305_KEYBYTES +
  crypto_secretstream_xchacha20poly1305_INONCEBYTES + crypto_secretstream_xchacha20poly1305_COUNTERBYTES + 8

const KEY_OFFSET = 0
const NONCE_OFFSET = crypto_secretstream_xchacha20poly1305_KEYBYTES
const PAD_OFFSET = NONCE_OFFSET + crypto_secretstream_xchacha20poly1305_INONCEBYTES + crypto_secretstream_xchacha20poly1305_COUNTERBYTES

const _pad0 = new Uint8Array(16)

function STORE64_LE (dest, int) {
  let mul = 1
  let i = 0
  dest[0] = int & 0xFF
  while (++i < 8 && (mul *= 0x100)) {
    dest[i] = (int / mul) & 0xFF
  }
}

function crypto_secretstream_xchacha20poly1305_counter_reset (state) {
  assert(state.byteLength === crypto_secretstream_xchacha20poly1305_STATEBYTES,
    'state is should be crypto_secretstream_xchacha20poly1305_STATEBYTES long')

  const nonce = state.subarray(NONCE_OFFSET, PAD_OFFSET)
  for (let i = 0; i < crypto_secretstream_xchacha20poly1305_COUNTERBYTES; i++) {
    nonce[i] = 0
  }
  nonce[0] = 1
}

function crypto_secretstream_xchacha20poly1305_keygen (k) {
  assert(k.length === crypto_secretstream_xchacha20poly1305_KEYBYTES)
  randombytes_buf(k)
}

function crypto_secretstream_xchacha20poly1305_init_push (state, out, key) {
  assert(state.byteLength === crypto_secretstream_xchacha20poly1305_STATEBYTES,
    'state is should be crypto_secretstream_xchacha20poly1305_STATEBYTES long')
  assert(out instanceof Uint8Array && out.length === crypto_secretstream_xchacha20poly1305_HEADERBYTES, 'out not byte array of length crypto_secretstream_xchacha20poly1305_HEADERBYTES')
  assert(key instanceof Uint8Array && key.length === crypto_secretstream_xchacha20poly1305_KEYBYTES, 'key not byte array of length crypto_secretstream_xchacha20poly1305_KEYBYTES')

  const k = state.subarray(KEY_OFFSET, NONCE_OFFSET)
  const nonce = state.subarray(NONCE_OFFSET, PAD_OFFSET)
  const pad = state.subarray(PAD_OFFSET)

  randombytes_buf(out, crypto_secretstream_xchacha20poly1305_HEADERBYTES)
  crypto_core_hchacha20(k, out, key, null)
  crypto_secretstream_xchacha20poly1305_counter_reset(state)
  for (let i = 0; i < crypto_secretstream_xchacha20poly1305_INONCEBYTES; i++) {
    nonce[i + crypto_secretstream_xchacha20poly1305_COUNTERBYTES] = out[i + crypto_core_hchacha20_INPUTBYTES]
  }
  pad.fill(0)
}

function crypto_secretstream_xchacha20poly1305_init_pull (state, _in, key) {
  assert(state.byteLength === crypto_secretstream_xchacha20poly1305_STATEBYTES,
    'state is should be crypto_secretstream_xchacha20poly1305_STATEBYTES long')
  assert(_in instanceof Uint8Array && _in.length === crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    '_in not byte array of length crypto_secretstream_xchacha20poly1305_HEADERBYTES')
  assert(key instanceof Uint8Array && key.length === crypto_secretstream_xchacha20poly1305_KEYBYTES,
    'key not byte array of length crypto_secretstream_xchacha20poly1305_KEYBYTES')

  const k = state.subarray(KEY_OFFSET, NONCE_OFFSET)
  const nonce = state.subarray(NONCE_OFFSET, PAD_OFFSET)
  const pad = state.subarray(PAD_OFFSET)

  crypto_core_hchacha20(k, _in, key, null)
  crypto_secretstream_xchacha20poly1305_counter_reset(state)

  for (let i = 0; i < crypto_secretstream_xchacha20poly1305_INONCEBYTES; i++) {
    nonce[i + crypto_secretstream_xchacha20poly1305_COUNTERBYTES] = _in[i + crypto_core_hchacha20_INPUTBYTES]
  }
  pad.fill(0)
}

function crypto_secretstream_xchacha20poly1305_rekey (state) {
  assert(state.byteLength === crypto_secretstream_xchacha20poly1305_STATEBYTES,
    'state is should be crypto_secretstream_xchacha20poly1305_STATEBYTES long')

  const k = state.subarray(KEY_OFFSET, NONCE_OFFSET)
  const nonce = state.subarray(NONCE_OFFSET, PAD_OFFSET)

  const new_key_and_inonce = new Uint8Array(
    crypto_stream_chacha20_ietf_KEYBYTES + crypto_secretstream_xchacha20poly1305_INONCEBYTES)
  let i
  for (i = 0; i < crypto_stream_chacha20_ietf_KEYBYTES; i++) {
    new_key_and_inonce[i] = k[i]
  }
  for (i = 0; i < crypto_secretstream_xchacha20poly1305_INONCEBYTES; i++) {
    new_key_and_inonce[crypto_stream_chacha20_ietf_KEYBYTES + i] =
      nonce[crypto_secretstream_xchacha20poly1305_COUNTERBYTES + i]
  }
  crypto_stream_chacha20_ietf_xor(new_key_and_inonce, new_key_and_inonce, nonce, k)
  for (i = 0; i < crypto_stream_chacha20_ietf_KEYBYTES; i++) {
    k[i] = new_key_and_inonce[i]
  }
  for (i = 0; i < crypto_secretstream_xchacha20poly1305_INONCEBYTES; i++) {
    nonce[crypto_secretstream_xchacha20poly1305_COUNTERBYTES + i] =
      new_key_and_inonce[crypto_stream_chacha20_ietf_KEYBYTES + i]
  }
  crypto_secretstream_xchacha20poly1305_counter_reset(state)
}

function crypto_secretstream_xchacha20poly1305_push (state, out, m, ad, tag) {
  assert(state.byteLength === crypto_secretstream_xchacha20poly1305_STATEBYTES,
    'state is should be crypto_secretstream_xchacha20poly1305_STATEBYTES long')
  if (!ad) ad = new Uint8Array(0)

  const k = state.subarray(KEY_OFFSET, NONCE_OFFSET)
  const nonce = state.subarray(NONCE_OFFSET, PAD_OFFSET)

  const block = new Uint8Array(64)
  const slen = new Uint8Array(8)

  assert(crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX <=
    crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX)

  crypto_stream_chacha20_ietf(block, nonce, k)
  const poly = new Poly1305(block)
  block.fill(0)

  poly.update(ad, 0, ad.byteLength)
  poly.update(_pad0, 0, (0x10 - ad.byteLength) & 0xf)

  block[0] = tag[0]
  crypto_stream_chacha20_ietf_xor_ic(block, block, nonce, 1, k)

  poly.update(block, 0, block.byteLength)
  out[0] = block[0]

  const c = out.subarray(1, out.byteLength)
  crypto_stream_chacha20_ietf_xor_ic(c, m, nonce, 2, k)
  poly.update(c, 0, m.byteLength)
  poly.update(_pad0, 0, (0x10 - block.byteLength + m.byteLength) & 0xf)

  STORE64_LE(slen, ad.byteLength)
  poly.update(slen, 0, slen.byteLength)
  STORE64_LE(slen, block.byteLength + m.byteLength)
  poly.update(slen, 0, slen.byteLength)

  const mac = out.subarray(1 + m.byteLength, out.byteLength)
  poly.finish(mac, 0)

  assert(crypto_onetimeauth_poly1305_BYTES >=
    crypto_secretstream_xchacha20poly1305_INONCEBYTES)
  xor_buf(nonce.subarray(crypto_secretstream_xchacha20poly1305_COUNTERBYTES, nonce.length),
    mac, crypto_secretstream_xchacha20poly1305_INONCEBYTES)
  sodium_increment(nonce)

  if ((tag[0] & crypto_secretstream_xchacha20poly1305_TAG_REKEY) !== 0 ||
    sodium_is_zero(nonce.subarray(0, crypto_secretstream_xchacha20poly1305_COUNTERBYTES))) {
    crypto_secretstream_xchacha20poly1305_rekey(state)
  }

  return crypto_secretstream_xchacha20poly1305_ABYTES + m.byteLength
}

function crypto_secretstream_xchacha20poly1305_pull (state, m, tag, _in, ad) {
  assert(state.byteLength === crypto_secretstream_xchacha20poly1305_STATEBYTES,
    'state is should be crypto_secretstream_xchacha20poly1305_STATEBYTES long')
  if (!ad) ad = new Uint8Array(0)

  const k = state.subarray(KEY_OFFSET, NONCE_OFFSET)
  const nonce = state.subarray(NONCE_OFFSET, PAD_OFFSET)

  const block = new Uint8Array(64)
  const slen = new Uint8Array(8)
  const mac = new Uint8Array(crypto_onetimeauth_poly1305_BYTES)

  assert(_in.byteLength >= crypto_secretstream_xchacha20poly1305_ABYTES,
    'ciphertext is too short.')

  const mlen = _in.byteLength - crypto_secretstream_xchacha20poly1305_ABYTES
  crypto_stream_chacha20_ietf(block, nonce, k)
  const poly = new Poly1305(block)
  block.fill(0) // sodium_memzero(block, sizeof block);

  poly.update(ad, 0, ad.byteLength)
  poly.update(_pad0, 0, (0x10 - ad.byteLength) & 0xf)

  block.fill(0) // memset(block, 0, sizeof block);
  block[0] = _in[0]
  crypto_stream_chacha20_ietf_xor_ic(block, block, nonce, 1, k)

  tag[0] = block[0]
  block[0] = _in[0]
  poly.update(block, 0, block.byteLength)

  const c = _in.subarray(1, _in.length)
  poly.update(c, 0, mlen)

  poly.update(_pad0, 0, (0x10 - block.byteLength + mlen) & 0xf)

  STORE64_LE(slen, ad.byteLength)
  poly.update(slen, 0, slen.byteLength)
  STORE64_LE(slen, block.byteLength + m.byteLength)
  poly.update(slen, 0, slen.byteLength)

  poly.finish(mac, 0)
  const stored_mac = _in.subarray(1 + mlen, _in.length)

  if (!sodium_memcmp(mac, stored_mac)) {
    mac.fill(0)
    throw new Error('MAC could not be verified.')
  }

  crypto_stream_chacha20_ietf_xor_ic(m, c.subarray(0, m.length), nonce, 2, k)
  xor_buf(nonce.subarray(crypto_secretstream_xchacha20poly1305_COUNTERBYTES, nonce.length),
    mac, crypto_secretstream_xchacha20poly1305_INONCEBYTES)
  sodium_increment(nonce)

  if ((tag & crypto_secretstream_xchacha20poly1305_TAG_REKEY) !== 0 ||
    sodium_is_zero(nonce.subarray(0, crypto_secretstream_xchacha20poly1305_COUNTERBYTES))) {
    crypto_secretstream_xchacha20poly1305_rekey(state)
  }

  return mlen
}

function xor_buf (out, _in, n) {
  for (let i = 0; i < n; i++) {
    out[i] ^= _in[i]
  }
}

module.exports = {
  crypto_secretstream_xchacha20poly1305_keygen,
  crypto_secretstream_xchacha20poly1305_init_push,
  crypto_secretstream_xchacha20poly1305_init_pull,
  crypto_secretstream_xchacha20poly1305_rekey,
  crypto_secretstream_xchacha20poly1305_push,
  crypto_secretstream_xchacha20poly1305_pull,
  crypto_secretstream_xchacha20poly1305_STATEBYTES,
  crypto_secretstream_xchacha20poly1305_ABYTES,
  crypto_secretstream_xchacha20poly1305_HEADERBYTES,
  crypto_secretstream_xchacha20poly1305_KEYBYTES,
  crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX,
  crypto_secretstream_xchacha20poly1305_TAGBYTES,
  crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
  crypto_secretstream_xchacha20poly1305_TAG_PUSH,
  crypto_secretstream_xchacha20poly1305_TAG_REKEY,
  crypto_secretstream_xchacha20poly1305_TAG_FINAL
}

},{"./crypto_stream_chacha20":94,"./helpers":96,"./internal/hchacha20":99,"./internal/poly1305":100,"./randombytes":102,"nanoassert":51}],91:[function(require,module,exports){
var siphash = require('siphash24')

if (new Uint16Array([1])[0] !== 1) throw new Error('Big endian architecture is not supported.')

exports.crypto_shorthash_PRIMITIVE = 'siphash24'
exports.crypto_shorthash_BYTES = siphash.BYTES
exports.crypto_shorthash_KEYBYTES = siphash.KEYBYTES
exports.crypto_shorthash_WASM_SUPPORTED = siphash.WASM_SUPPORTED
exports.crypto_shorthash_WASM_LOADED = siphash.WASM_LOADED
exports.crypto_shorthash = shorthash

function shorthash (out, data, key, noAssert) {
  siphash(data, key, out, noAssert)
}

},{"siphash24":77}],92:[function(require,module,exports){
/* eslint-disable camelcase, one-var */
const { crypto_verify_32 } = require('./crypto_verify')
const { crypto_hash } = require('./crypto_hash')
const {
  gf, gf0, gf1, D, D2,
  X, Y, I, A, Z, M, S,
  sel25519, pack25519,
  inv25519, unpack25519
} = require('./internal/ed25519')
const { randombytes } = require('./randombytes')
const { crypto_scalarmult_BYTES } = require('./crypto_scalarmult.js')
const { crypto_hash_sha512_BYTES } = require('./crypto_hash.js')
const assert = require('nanoassert')

const crypto_sign_ed25519_PUBLICKEYBYTES = 32
const crypto_sign_ed25519_SECRETKEYBYTES = 64
const crypto_sign_ed25519_SEEDBYTES = 32
const crypto_sign_ed25519_BYTES = 64

const crypto_sign_BYTES = crypto_sign_ed25519_BYTES
const crypto_sign_PUBLICKEYBYTES = crypto_sign_ed25519_PUBLICKEYBYTES
const crypto_sign_SECRETKEYBYTES = crypto_sign_ed25519_SECRETKEYBYTES
const crypto_sign_SEEDBYTES = crypto_sign_ed25519_SEEDBYTES

module.exports = {
  crypto_sign_keypair,
  crypto_sign_seed_keypair,
  crypto_sign,
  crypto_sign_detached,
  crypto_sign_open,
  crypto_sign_verify_detached,
  crypto_sign_BYTES,
  crypto_sign_PUBLICKEYBYTES,
  crypto_sign_SECRETKEYBYTES,
  crypto_sign_SEEDBYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_pk_to_curve25519,
  crypto_sign_ed25519_sk_to_curve25519,
  crypto_sign_ed25519_sk_to_pk,
  unpackneg,
  pack
}

function set25519 (r, a) {
  for (let i = 0; i < 16; i++) r[i] = a[i] | 0
}

function pow2523 (o, i) {
  var c = gf()
  var a
  for (a = 0; a < 16; a++) c[a] = i[a]
  for (a = 250; a >= 0; a--) {
    S(c, c)
    if (a !== 1) M(c, c, i)
  }
  for (a = 0; a < 16; a++) o[a] = c[a]
}

function add (p, q) {
  var a = gf(), b = gf(), c = gf(),
    d = gf(), e = gf(), f = gf(),
    g = gf(), h = gf(), t = gf()

  Z(a, p[1], p[0])
  Z(t, q[1], q[0])
  M(a, a, t)
  A(b, p[0], p[1])
  A(t, q[0], q[1])
  M(b, b, t)
  M(c, p[3], q[3])
  M(c, c, D2)
  M(d, p[2], q[2])
  A(d, d, d)
  Z(e, b, a)
  Z(f, d, c)
  A(g, d, c)
  A(h, b, a)

  M(p[0], e, f)
  M(p[1], h, g)
  M(p[2], g, f)
  M(p[3], e, h)
}

function cswap (p, q, b) {
  var i
  for (i = 0; i < 4; i++) {
    sel25519(p[i], q[i], b)
  }
}

function pack (r, p) {
  var tx = gf(), ty = gf(), zi = gf()
  inv25519(zi, p[2])
  M(tx, p[0], zi)
  M(ty, p[1], zi)
  pack25519(r, ty)
  r[31] ^= par25519(tx) << 7
}

function scalarmult (p, q, s) {
  // don't mutate q
  var h = [gf(q[0]), gf(q[1]), gf(q[2]), gf(q[3])]
  var b, i
  set25519(p[0], gf0)
  set25519(p[1], gf1)
  set25519(p[2], gf1)
  set25519(p[3], gf0)
  for (i = 255; i >= 0; --i) {
    b = (s[(i / 8) | 0] >> (i & 7)) & 1
    cswap(p, h, b)
    add(h, p)
    add(p, p)
    cswap(p, h, b)
  }
}

function scalarbase (p, s) {
  var q = [gf(), gf(), gf(), gf()]
  set25519(q[0], X)
  set25519(q[1], Y)
  set25519(q[2], gf1)
  M(q[3], X, Y)
  scalarmult(p, q, s)
}

function crypto_sign_keypair (pk, sk, seeded) {
  check(pk, crypto_sign_PUBLICKEYBYTES)
  check(sk, crypto_sign_SECRETKEYBYTES)

  var d = new Uint8Array(64)
  var p = [gf(), gf(), gf(), gf()]
  var i

  if (!seeded) randombytes(sk, 32)
  crypto_hash(d, sk, 32)
  d[0] &= 248
  d[31] &= 127
  d[31] |= 64

  scalarbase(p, d)
  pack(pk, p)

  for (i = 0; i < 32; i++) sk[i + 32] = pk[i]
}

function crypto_sign_seed_keypair (pk, sk, seed) {
  check(seed, crypto_sign_SEEDBYTES)
  sk.set(seed)
  return crypto_sign_keypair(pk, sk, true)
}

var L = new Float64Array([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10])

function modL (r, x) {
  var carry, i, j, k
  for (i = 63; i >= 32; --i) {
    carry = 0
    for (j = i - 32, k = i - 12; j < k; ++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)]
      carry = (x[j] + 128) >> 8
      x[j] -= carry * 256
    }
    x[j] += carry
    x[i] = 0
  }
  carry = 0
  for (j = 0; j < 32; j++) {
    x[j] += carry - (x[31] >> 4) * L[j]
    carry = x[j] >> 8
    x[j] &= 255
  }
  for (j = 0; j < 32; j++) x[j] -= carry * L[j]
  for (i = 0; i < 32; i++) {
    x[i + 1] += x[i] >> 8
    r[i] = x[i] & 255
  }
}

function reduce (r) {
  var x = new Float64Array(64)
  for (let i = 0; i < 64; i++) x[i] = r[i]
  for (let i = 0; i < 64; i++) r[i] = 0
  modL(r, x)
}

// Note: difference from C - smlen returned, not passed as argument.
function crypto_sign (sm, m, sk) {
  check(sm, crypto_sign_BYTES + m.length)
  check(m, 0)
  check(sk, crypto_sign_SECRETKEYBYTES)
  var n = m.length

  var d = new Uint8Array(64), h = new Uint8Array(64), r = new Uint8Array(64)
  var i, j, x = new Float64Array(64)
  var p = [gf(), gf(), gf(), gf()]

  crypto_hash(d, sk, 32)
  d[0] &= 248
  d[31] &= 127
  d[31] |= 64

  var smlen = n + 64
  for (i = 0; i < n; i++) sm[64 + i] = m[i]
  for (i = 0; i < 32; i++) sm[32 + i] = d[32 + i]

  crypto_hash(r, sm.subarray(32), n + 32)
  reduce(r)
  scalarbase(p, r)
  pack(sm, p)

  for (i = 32; i < 64; i++) sm[i] = sk[i]
  crypto_hash(h, sm, n + 64)
  reduce(h)

  for (i = 0; i < 64; i++) x[i] = 0
  for (i = 0; i < 32; i++) x[i] = r[i]
  for (i = 0; i < 32; i++) {
    for (j = 0; j < 32; j++) {
      x[i + j] += h[i] * d[j]
    }
  }

  modL(sm.subarray(32), x)
  return smlen
}

function crypto_sign_detached (sig, m, sk) {
  var sm = new Uint8Array(m.length + crypto_sign_BYTES)
  crypto_sign(sm, m, sk)
  for (let i = 0; i < crypto_sign_BYTES; i++) sig[i] = sm[i]
}

function unpackneg (r, p) {
  var t = gf(), chk = gf(), num = gf(),
    den = gf(), den2 = gf(), den4 = gf(),
    den6 = gf()

  set25519(r[2], gf1)
  unpack25519(r[1], p)
  S(num, r[1])
  M(den, num, D)
  Z(num, num, r[2])
  A(den, r[2], den)

  S(den2, den)
  S(den4, den2)
  M(den6, den4, den2)
  M(t, den6, num)
  M(t, t, den)

  pow2523(t, t)
  M(t, t, num)
  M(t, t, den)
  M(t, t, den)
  M(r[0], t, den)

  S(chk, r[0])
  M(chk, chk, den)
  if (!neq25519(chk, num)) M(r[0], r[0], I)

  S(chk, r[0])
  M(chk, chk, den)
  if (!neq25519(chk, num)) return false

  if (par25519(r[0]) === (p[31] >> 7)) {
    Z(r[0], gf(), r[0])
  }

  M(r[3], r[0], r[1])
  return true
}

/* eslint-disable no-unused-vars */
function crypto_sign_open (msg, sm, pk) {
  check(msg, sm.length - crypto_sign_BYTES)
  check(sm, crypto_sign_BYTES)
  check(pk, crypto_sign_PUBLICKEYBYTES)
  var n = sm.length
  var m = new Uint8Array(sm.length)

  var i, mlen
  var t = new Uint8Array(32), h = new Uint8Array(64)
  var p = [gf(), gf(), gf(), gf()],
    q = [gf(), gf(), gf(), gf()]

  mlen = -1
  if (n < 64) return false

  if (!unpackneg(q, pk)) return false

  for (i = 0; i < n; i++) m[i] = sm[i]
  for (i = 0; i < 32; i++) m[i + 32] = pk[i]
  crypto_hash(h, m, n)
  reduce(h)
  scalarmult(p, q, h)

  scalarbase(q, sm.subarray(32))
  add(p, q)
  pack(t, p)

  n -= 64
  if (!crypto_verify_32(sm, 0, t, 0)) {
    for (i = 0; i < n; i++) m[i] = 0
    return false
    // throw new Error('crypto_sign_open failed')
  }

  for (i = 0; i < n; i++) msg[i] = sm[i + 64]
  mlen = n
  return true
}
/* eslint-enable no-unused-vars */

function crypto_sign_verify_detached (sig, m, pk) {
  check(sig, crypto_sign_BYTES)
  var sm = new Uint8Array(m.length + crypto_sign_BYTES)
  var i = 0
  for (i = 0; i < crypto_sign_BYTES; i++) sm[i] = sig[i]
  for (i = 0; i < m.length; i++) sm[i + crypto_sign_BYTES] = m[i]
  return crypto_sign_open(m, sm, pk)
}

function par25519 (a) {
  var d = new Uint8Array(32)
  pack25519(d, a)
  return d[0] & 1
}

function neq25519 (a, b) {
  var c = new Uint8Array(32), d = new Uint8Array(32)
  pack25519(c, a)
  pack25519(d, b)
  return crypto_verify_32(c, 0, d, 0)
}

function ed25519_mul_l (p, q) {
  scalarmult(p, q, L)
}

function ed25519_is_on_main_subgroup (p) {
  var pl = [gf(), gf(), gf(), gf()]

  ed25519_mul_l(pl, p)

  var zero = 0
  for (let i = 0; i < 16; i++) {
    zero |= (pl[0][i] & 0xffff)
  }

  return zero === 0
}

function crypto_sign_ed25519_pk_to_curve25519 (x25519_pk, ed25519_pk) {
  check(x25519_pk, crypto_sign_PUBLICKEYBYTES)
  check(ed25519_pk, crypto_sign_ed25519_PUBLICKEYBYTES)

  var a = [gf(), gf(), gf(), gf()]
  var x = gf([1])
  var one_minus_y = gf([1])

  assert(
    isSmallOrder(ed25519_pk) &&
    unpackneg(a, ed25519_pk) &&
    ed25519_is_on_main_subgroup(a), 'Cannot convert key: bad point')

  for (let i = 0; i < a.length; i++) {
    pack25519(x25519_pk, a[i])
  }

  Z(one_minus_y, one_minus_y, a[1])
  A(x, x, a[1])
  inv25519(one_minus_y, one_minus_y)
  M(x, x, one_minus_y)
  pack25519(x25519_pk, x)

  return 0
}

function isSmallOrder (s) {
  Uint8Array.from([])

  var bad_points = [
    // 0 (order 4)
    Uint8Array.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),

    // 1 (order 1)
    Uint8Array.from([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),

    // 2707385501144840649318225287225658788936804267575313519463743609750303402022(order 8)
    Uint8Array.from([0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3,
      0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3,
      0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05]),

    // 55188659117513257062467267217118295137698188065244968500265048394206261417927 (order 8)
    Uint8Array.from([0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c,
      0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c,
      0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a]),

    // p-1 (order 2)
    Uint8Array.from([0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),

    //  p (=0 order 4)
    Uint8Array.from([0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),

    // p + 1 (=1 order 1)
    Uint8Array.from([0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f])
  ]

  var c = new Uint8Array(7)
  var j

  check(bad_points, 7)
  for (let i = 0; i < bad_points.length; i++) {
    for (j = 0; j < 31; j++) {
      c[i] |= s[j] ^ bad_points[i][j]
    }
  }

  for (let i = 0; i < bad_points.length; i++) {
    c[i] |= (s[j] & 0x7f) ^ bad_points[i][j]
  }

  var k = 0
  for (let i = 0; i < bad_points.length; i++) {
    k |= (c[i] - 1)
  }

  return ((k >> 8) & 1) === 0
}

function crypto_sign_ed25519_sk_to_pk (pk, sk) {
  check(pk, crypto_sign_ed25519_PUBLICKEYBYTES)
  pk.set(sk.subarray(crypto_sign_ed25519_SEEDBYTES))
  return pk
}

function crypto_sign_ed25519_sk_to_curve25519 (curveSk, edSk) {
  assert(curveSk && curveSk.byteLength === crypto_scalarmult_BYTES, "curveSk must be 'crypto_sign_SECRETKEYBYTES' long")
  assert(edSk && edSk.byteLength === crypto_sign_ed25519_SECRETKEYBYTES, "edSk must be 'crypto_sign_ed25519_SECRETKEYBYTES' long")

  var h = new Uint8Array(crypto_hash_sha512_BYTES)
  crypto_hash(h, edSk, 32)

  h[0] &= 248
  h[31] &= 127
  h[31] |= 64

  curveSk.set(h.subarray(0, crypto_scalarmult_BYTES))
  h.fill(0)
  return curveSk
}

function check (buf, len, arg = 'Argument') {
  if (!buf || (len && buf.length < len)) throw new Error(arg + ' must be a buffer' + (len ? ' of length ' + len : ''))
}

},{"./crypto_hash":83,"./crypto_hash.js":83,"./crypto_scalarmult.js":88,"./crypto_verify":95,"./internal/ed25519":98,"./randombytes":102,"nanoassert":51}],93:[function(require,module,exports){
/* eslint-disable camelcase */
const xsalsa20 = require('xsalsa20')

if (new Uint16Array([1])[0] !== 1) throw new Error('Big endian architecture is not supported.')

exports.crypto_stream_KEYBYTES = 32
exports.crypto_stream_NONCEBYTES = 24
exports.crypto_stream_PRIMITIVE = 'xsalsa20'
exports.crypto_stream_xsalsa20_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER

exports.crypto_stream = function (c, nonce, key) {
  c.fill(0)
  exports.crypto_stream_xor(c, c, nonce, key)
}

exports.crypto_stream_xor = function (c, m, nonce, key) {
  const xor = xsalsa20(nonce, key)

  xor.update(m, c)
  xor.final()
}

exports.crypto_stream_xor_instance = function (nonce, key) {
  return new XOR(nonce, key)
}

function XOR (nonce, key) {
  this._instance = xsalsa20(nonce, key)
}

XOR.prototype.update = function (out, inp) {
  this._instance.update(inp, out)
}

XOR.prototype.final = function () {
  this._instance.finalize()
  this._instance = null
}

},{"xsalsa20":131}],94:[function(require,module,exports){
const assert = require('nanoassert')
const Chacha20 = require('chacha20-universal')

if (new Uint16Array([1])[0] !== 1) throw new Error('Big endian architecture is not supported.')

exports.crypto_stream_chacha20_KEYBYTES = 32
exports.crypto_stream_chacha20_NONCEBYTES = 8
exports.crypto_stream_chacha20_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER

exports.crypto_stream_chacha20_ietf_KEYBYTES = 32
exports.crypto_stream_chacha20_ietf_NONCEBYTES = 12
exports.crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX = 2 ** 32

exports.crypto_stream_chacha20 = function (c, n, k) {
  c.fill(0)
  exports.crypto_stream_chacha20_xor(c, c, n, k)
}

exports.crypto_stream_chacha20_xor = function (c, m, n, k) {
  assert(n.byteLength === exports.crypto_stream_chacha20_NONCEBYTES,
    'n should be crypto_stream_chacha20_NONCEBYTES')
  assert(k.byteLength === exports.crypto_stream_chacha20_KEYBYTES,
    'k should be crypto_stream_chacha20_KEYBYTES')

  const xor = new Chacha20(n, k)
  xor.update(c, m)
  xor.final()
}

exports.crypto_stream_chacha20_xor_ic = function (c, m, n, ic, k) {
  assert(n.byteLength === exports.crypto_stream_chacha20_NONCEBYTES,
    'n should be crypto_stream_chacha20_NONCEBYTES')
  assert(k.byteLength === exports.crypto_stream_chacha20_KEYBYTES,
    'k should be crypto_stream_chacha20_KEYBYTES')

  const xor = new Chacha20(n, k, ic)
  xor.update(c, m)
  xor.final()
}

exports.crypto_stream_chacha20_xor_instance = function (n, k) {
  assert(n.byteLength === exports.crypto_stream_chacha20_NONCEBYTES,
    'n should be crypto_stream_chacha20_NONCEBYTES')
  assert(k.byteLength === exports.crypto_stream_chacha20_KEYBYTES,
    'k should be crypto_stream_chacha20_KEYBYTES')

  return new Chacha20(n, k)
}

exports.crypto_stream_chacha20_ietf = function (c, n, k) {
  c.fill(0)
  exports.crypto_stream_chacha20_ietf_xor(c, c, n, k)
}

exports.crypto_stream_chacha20_ietf_xor = function (c, m, n, k) {
  assert(n.byteLength === exports.crypto_stream_chacha20_ietf_NONCEBYTES,
    'n should be crypto_stream_chacha20_ietf_NONCEBYTES')
  assert(k.byteLength === exports.crypto_stream_chacha20_ietf_KEYBYTES,
    'k should be crypto_stream_chacha20_ietf_KEYBYTES')

  const xor = new Chacha20(n, k)
  xor.update(c, m)
  xor.final()
}

exports.crypto_stream_chacha20_ietf_xor_ic = function (c, m, n, ic, k) {
  assert(n.byteLength === exports.crypto_stream_chacha20_ietf_NONCEBYTES,
    'n should be crypto_stream_chacha20_ietf_NONCEBYTES')
  assert(k.byteLength === exports.crypto_stream_chacha20_ietf_KEYBYTES,
    'k should be crypto_stream_chacha20_ietf_KEYBYTES')

  const xor = new Chacha20(n, k, ic)
  xor.update(c, m)
  xor.final()
}

exports.crypto_stream_chacha20_ietf_xor_instance = function (n, k) {
  assert(n.byteLength === exports.crypto_stream_chacha20_ietf_NONCEBYTES,
    'n should be crypto_stream_chacha20_ietf_NONCEBYTES')
  assert(k.byteLength === exports.crypto_stream_chacha20_ietf_KEYBYTES,
    'k should be crypto_stream_chacha20_ietf_KEYBYTES')

  return new Chacha20(n, k)
}

},{"chacha20-universal":14,"nanoassert":51}],95:[function(require,module,exports){
/* eslint-disable camelcase */
module.exports = {
  crypto_verify_16,
  crypto_verify_32,
  crypto_verify_64
}

function vn (x, xi, y, yi, n) {
  var d = 0
  for (let i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i]
  return (1 & ((d - 1) >>> 8)) - 1
}

// Make non enumerable as this is an internal function
Object.defineProperty(module.exports, 'vn', {
  value: vn
})

function crypto_verify_16 (x, xi, y, yi) {
  return vn(x, xi, y, yi, 16) === 0
}

function crypto_verify_32 (x, xi, y, yi) {
  return vn(x, xi, y, yi, 32) === 0
}

function crypto_verify_64 (x, xi, y, yi) {
  return vn(x, xi, y, yi, 64) === 0
}

},{}],96:[function(require,module,exports){
/* eslint-disable camelcase */
const assert = require('nanoassert')
const { vn } = require('./crypto_verify')

function sodium_increment (n) {
  const nlen = n.byteLength
  var c = 1
  for (var i = 0; i < nlen; i++) {
    c += n[i]
    n[i] = c
    c >>= 8
  }
}

function sodium_memcmp (a, b) {
  assert(a.byteLength === b.byteLength, 'buffers must be the same size')

  return vn(a, 0, b, 0, a.byteLength) === 0
}

function sodium_is_zero (arr) {
  var d = 0
  for (let i = 0; i < arr.length; i++) d |= arr[i]
  return d === 0
}

module.exports = {
  sodium_increment,
  sodium_memcmp,
  sodium_is_zero
}

},{"./crypto_verify":95,"nanoassert":51}],97:[function(require,module,exports){
'use strict'

// Based on https://github.com/dchest/tweetnacl-js/blob/6dcbcaf5f5cbfd313f2dcfe763db35c828c8ff5b/nacl-fast.js.

// Ported in 2014 by Dmitry Chestnykh and Devi Mandiri.
// Public domain.
//
// Implementation derived from TweetNaCl version 20140427.
// See for details: http://tweetnacl.cr.yp.to/

forward(require('./randombytes'))
forward(require('./memory'))
forward(require('./helpers'))
forward(require('./crypto_verify'))
forward(require('./crypto_auth'))
forward(require('./crypto_box'))
forward(require('./crypto_generichash'))
forward(require('./crypto_hash'))
forward(require('./crypto_hash_sha256'))
forward(require('./crypto_kdf'))
forward(require('./crypto_kx'))
forward(require('./crypto_aead'))
forward(require('./crypto_onetimeauth'))
forward(require('./crypto_scalarmult'))
forward(require('./crypto_secretbox'))
forward(require('./crypto_secretstream'))
forward(require('./crypto_shorthash'))
forward(require('./crypto_sign'))
forward(require('./crypto_stream'))
forward(require('./crypto_stream_chacha20'))

function forward (submodule) {
  Object.keys(submodule).forEach(function (prop) {
    module.exports[prop] = submodule[prop]
  })
}

},{"./crypto_aead":79,"./crypto_auth":80,"./crypto_box":81,"./crypto_generichash":82,"./crypto_hash":83,"./crypto_hash_sha256":84,"./crypto_kdf":85,"./crypto_kx":86,"./crypto_onetimeauth":87,"./crypto_scalarmult":88,"./crypto_secretbox":89,"./crypto_secretstream":90,"./crypto_shorthash":91,"./crypto_sign":92,"./crypto_stream":93,"./crypto_stream_chacha20":94,"./crypto_verify":95,"./helpers":96,"./memory":101,"./randombytes":102}],98:[function(require,module,exports){
if (new Uint16Array([1])[0] !== 1) throw new Error('Big endian architecture is not supported.')

var gf = function(init) {
  var i, r = new Float64Array(16);
  if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
  return r;
}

var _0 = new Uint8Array(16);
var _9 = new Uint8Array(32); _9[0] = 9;

var gf0 = gf(),
    gf1 = gf([1]),
    _121665 = gf([0xdb41, 1]),
    D = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]),
    D2 = gf([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]),
    X = gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]),
    Y = gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]),
    I = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]);

function A(o, a, b) {
  for (var i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

function Z(o, a, b) {
  for (var i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

function M(o, a, b) {
  var v, c,
    t0 = 0,  t1 = 0,  t2 = 0,  t3 = 0,  t4 = 0,  t5 = 0,  t6 = 0,  t7 = 0,
    t8 = 0,  t9 = 0, t10 = 0, t11 = 0, t12 = 0, t13 = 0, t14 = 0, t15 = 0,
    t16 = 0, t17 = 0, t18 = 0, t19 = 0, t20 = 0, t21 = 0, t22 = 0, t23 = 0,
    t24 = 0, t25 = 0, t26 = 0, t27 = 0, t28 = 0, t29 = 0, t30 = 0,
    b0 = b[0],
    b1 = b[1],
    b2 = b[2],
    b3 = b[3],
    b4 = b[4],
    b5 = b[5],
    b6 = b[6],
    b7 = b[7],
    b8 = b[8],
    b9 = b[9],
    b10 = b[10],
    b11 = b[11],
    b12 = b[12],
    b13 = b[13],
    b14 = b[14],
    b15 = b[15];

  v = a[0];
  t0 += v * b0;
  t1 += v * b1;
  t2 += v * b2;
  t3 += v * b3;
  t4 += v * b4;
  t5 += v * b5;
  t6 += v * b6;
  t7 += v * b7;
  t8 += v * b8;
  t9 += v * b9;
  t10 += v * b10;
  t11 += v * b11;
  t12 += v * b12;
  t13 += v * b13;
  t14 += v * b14;
  t15 += v * b15;
  v = a[1];
  t1 += v * b0;
  t2 += v * b1;
  t3 += v * b2;
  t4 += v * b3;
  t5 += v * b4;
  t6 += v * b5;
  t7 += v * b6;
  t8 += v * b7;
  t9 += v * b8;
  t10 += v * b9;
  t11 += v * b10;
  t12 += v * b11;
  t13 += v * b12;
  t14 += v * b13;
  t15 += v * b14;
  t16 += v * b15;
  v = a[2];
  t2 += v * b0;
  t3 += v * b1;
  t4 += v * b2;
  t5 += v * b3;
  t6 += v * b4;
  t7 += v * b5;
  t8 += v * b6;
  t9 += v * b7;
  t10 += v * b8;
  t11 += v * b9;
  t12 += v * b10;
  t13 += v * b11;
  t14 += v * b12;
  t15 += v * b13;
  t16 += v * b14;
  t17 += v * b15;
  v = a[3];
  t3 += v * b0;
  t4 += v * b1;
  t5 += v * b2;
  t6 += v * b3;
  t7 += v * b4;
  t8 += v * b5;
  t9 += v * b6;
  t10 += v * b7;
  t11 += v * b8;
  t12 += v * b9;
  t13 += v * b10;
  t14 += v * b11;
  t15 += v * b12;
  t16 += v * b13;
  t17 += v * b14;
  t18 += v * b15;
  v = a[4];
  t4 += v * b0;
  t5 += v * b1;
  t6 += v * b2;
  t7 += v * b3;
  t8 += v * b4;
  t9 += v * b5;
  t10 += v * b6;
  t11 += v * b7;
  t12 += v * b8;
  t13 += v * b9;
  t14 += v * b10;
  t15 += v * b11;
  t16 += v * b12;
  t17 += v * b13;
  t18 += v * b14;
  t19 += v * b15;
  v = a[5];
  t5 += v * b0;
  t6 += v * b1;
  t7 += v * b2;
  t8 += v * b3;
  t9 += v * b4;
  t10 += v * b5;
  t11 += v * b6;
  t12 += v * b7;
  t13 += v * b8;
  t14 += v * b9;
  t15 += v * b10;
  t16 += v * b11;
  t17 += v * b12;
  t18 += v * b13;
  t19 += v * b14;
  t20 += v * b15;
  v = a[6];
  t6 += v * b0;
  t7 += v * b1;
  t8 += v * b2;
  t9 += v * b3;
  t10 += v * b4;
  t11 += v * b5;
  t12 += v * b6;
  t13 += v * b7;
  t14 += v * b8;
  t15 += v * b9;
  t16 += v * b10;
  t17 += v * b11;
  t18 += v * b12;
  t19 += v * b13;
  t20 += v * b14;
  t21 += v * b15;
  v = a[7];
  t7 += v * b0;
  t8 += v * b1;
  t9 += v * b2;
  t10 += v * b3;
  t11 += v * b4;
  t12 += v * b5;
  t13 += v * b6;
  t14 += v * b7;
  t15 += v * b8;
  t16 += v * b9;
  t17 += v * b10;
  t18 += v * b11;
  t19 += v * b12;
  t20 += v * b13;
  t21 += v * b14;
  t22 += v * b15;
  v = a[8];
  t8 += v * b0;
  t9 += v * b1;
  t10 += v * b2;
  t11 += v * b3;
  t12 += v * b4;
  t13 += v * b5;
  t14 += v * b6;
  t15 += v * b7;
  t16 += v * b8;
  t17 += v * b9;
  t18 += v * b10;
  t19 += v * b11;
  t20 += v * b12;
  t21 += v * b13;
  t22 += v * b14;
  t23 += v * b15;
  v = a[9];
  t9 += v * b0;
  t10 += v * b1;
  t11 += v * b2;
  t12 += v * b3;
  t13 += v * b4;
  t14 += v * b5;
  t15 += v * b6;
  t16 += v * b7;
  t17 += v * b8;
  t18 += v * b9;
  t19 += v * b10;
  t20 += v * b11;
  t21 += v * b12;
  t22 += v * b13;
  t23 += v * b14;
  t24 += v * b15;
  v = a[10];
  t10 += v * b0;
  t11 += v * b1;
  t12 += v * b2;
  t13 += v * b3;
  t14 += v * b4;
  t15 += v * b5;
  t16 += v * b6;
  t17 += v * b7;
  t18 += v * b8;
  t19 += v * b9;
  t20 += v * b10;
  t21 += v * b11;
  t22 += v * b12;
  t23 += v * b13;
  t24 += v * b14;
  t25 += v * b15;
  v = a[11];
  t11 += v * b0;
  t12 += v * b1;
  t13 += v * b2;
  t14 += v * b3;
  t15 += v * b4;
  t16 += v * b5;
  t17 += v * b6;
  t18 += v * b7;
  t19 += v * b8;
  t20 += v * b9;
  t21 += v * b10;
  t22 += v * b11;
  t23 += v * b12;
  t24 += v * b13;
  t25 += v * b14;
  t26 += v * b15;
  v = a[12];
  t12 += v * b0;
  t13 += v * b1;
  t14 += v * b2;
  t15 += v * b3;
  t16 += v * b4;
  t17 += v * b5;
  t18 += v * b6;
  t19 += v * b7;
  t20 += v * b8;
  t21 += v * b9;
  t22 += v * b10;
  t23 += v * b11;
  t24 += v * b12;
  t25 += v * b13;
  t26 += v * b14;
  t27 += v * b15;
  v = a[13];
  t13 += v * b0;
  t14 += v * b1;
  t15 += v * b2;
  t16 += v * b3;
  t17 += v * b4;
  t18 += v * b5;
  t19 += v * b6;
  t20 += v * b7;
  t21 += v * b8;
  t22 += v * b9;
  t23 += v * b10;
  t24 += v * b11;
  t25 += v * b12;
  t26 += v * b13;
  t27 += v * b14;
  t28 += v * b15;
  v = a[14];
  t14 += v * b0;
  t15 += v * b1;
  t16 += v * b2;
  t17 += v * b3;
  t18 += v * b4;
  t19 += v * b5;
  t20 += v * b6;
  t21 += v * b7;
  t22 += v * b8;
  t23 += v * b9;
  t24 += v * b10;
  t25 += v * b11;
  t26 += v * b12;
  t27 += v * b13;
  t28 += v * b14;
  t29 += v * b15;
  v = a[15];
  t15 += v * b0;
  t16 += v * b1;
  t17 += v * b2;
  t18 += v * b3;
  t19 += v * b4;
  t20 += v * b5;
  t21 += v * b6;
  t22 += v * b7;
  t23 += v * b8;
  t24 += v * b9;
  t25 += v * b10;
  t26 += v * b11;
  t27 += v * b12;
  t28 += v * b13;
  t29 += v * b14;
  t30 += v * b15;

  t0  += 38 * t16;
  t1  += 38 * t17;
  t2  += 38 * t18;
  t3  += 38 * t19;
  t4  += 38 * t20;
  t5  += 38 * t21;
  t6  += 38 * t22;
  t7  += 38 * t23;
  t8  += 38 * t24;
  t9  += 38 * t25;
  t10 += 38 * t26;
  t11 += 38 * t27;
  t12 += 38 * t28;
  t13 += 38 * t29;
  t14 += 38 * t30;
  // t15 left as is

  // first car
  c = 1;
  v =  t0 + c + 65535; c = Math.floor(v / 65536);  t0 = v - c * 65536;
  v =  t1 + c + 65535; c = Math.floor(v / 65536);  t1 = v - c * 65536;
  v =  t2 + c + 65535; c = Math.floor(v / 65536);  t2 = v - c * 65536;
  v =  t3 + c + 65535; c = Math.floor(v / 65536);  t3 = v - c * 65536;
  v =  t4 + c + 65535; c = Math.floor(v / 65536);  t4 = v - c * 65536;
  v =  t5 + c + 65535; c = Math.floor(v / 65536);  t5 = v - c * 65536;
  v =  t6 + c + 65535; c = Math.floor(v / 65536);  t6 = v - c * 65536;
  v =  t7 + c + 65535; c = Math.floor(v / 65536);  t7 = v - c * 65536;
  v =  t8 + c + 65535; c = Math.floor(v / 65536);  t8 = v - c * 65536;
  v =  t9 + c + 65535; c = Math.floor(v / 65536);  t9 = v - c * 65536;
  v = t10 + c + 65535; c = Math.floor(v / 65536); t10 = v - c * 65536;
  v = t11 + c + 65535; c = Math.floor(v / 65536); t11 = v - c * 65536;
  v = t12 + c + 65535; c = Math.floor(v / 65536); t12 = v - c * 65536;
  v = t13 + c + 65535; c = Math.floor(v / 65536); t13 = v - c * 65536;
  v = t14 + c + 65535; c = Math.floor(v / 65536); t14 = v - c * 65536;
  v = t15 + c + 65535; c = Math.floor(v / 65536); t15 = v - c * 65536;
  t0 += c-1 + 37 * (c-1);

  // second car
  c = 1;
  v =  t0 + c + 65535; c = Math.floor(v / 65536);  t0 = v - c * 65536;
  v =  t1 + c + 65535; c = Math.floor(v / 65536);  t1 = v - c * 65536;
  v =  t2 + c + 65535; c = Math.floor(v / 65536);  t2 = v - c * 65536;
  v =  t3 + c + 65535; c = Math.floor(v / 65536);  t3 = v - c * 65536;
  v =  t4 + c + 65535; c = Math.floor(v / 65536);  t4 = v - c * 65536;
  v =  t5 + c + 65535; c = Math.floor(v / 65536);  t5 = v - c * 65536;
  v =  t6 + c + 65535; c = Math.floor(v / 65536);  t6 = v - c * 65536;
  v =  t7 + c + 65535; c = Math.floor(v / 65536);  t7 = v - c * 65536;
  v =  t8 + c + 65535; c = Math.floor(v / 65536);  t8 = v - c * 65536;
  v =  t9 + c + 65535; c = Math.floor(v / 65536);  t9 = v - c * 65536;
  v = t10 + c + 65535; c = Math.floor(v / 65536); t10 = v - c * 65536;
  v = t11 + c + 65535; c = Math.floor(v / 65536); t11 = v - c * 65536;
  v = t12 + c + 65535; c = Math.floor(v / 65536); t12 = v - c * 65536;
  v = t13 + c + 65535; c = Math.floor(v / 65536); t13 = v - c * 65536;
  v = t14 + c + 65535; c = Math.floor(v / 65536); t14 = v - c * 65536;
  v = t15 + c + 65535; c = Math.floor(v / 65536); t15 = v - c * 65536;
  t0 += c-1 + 37 * (c-1);

  o[ 0] = t0;
  o[ 1] = t1;
  o[ 2] = t2;
  o[ 3] = t3;
  o[ 4] = t4;
  o[ 5] = t5;
  o[ 6] = t6;
  o[ 7] = t7;
  o[ 8] = t8;
  o[ 9] = t9;
  o[10] = t10;
  o[11] = t11;
  o[12] = t12;
  o[13] = t13;
  o[14] = t14;
  o[15] = t15;
}

function S(o, a) {
  M(o, a, a);
}

function sel25519(p, q, b) {
  var t, c = ~(b-1);
  for (var i = 0; i < 16; i++) {
    t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

function pack25519(o, n) {
  var i, j, b;
  var m = gf(), t = gf();
  for (i = 0; i < 16; i++) t[i] = n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  for (j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed;
    for (i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i-1]>>16) & 1);
      m[i-1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14]>>16) & 1);
    b = (m[15]>>16) & 1;
    m[14] &= 0xffff;
    sel25519(t, m, 1-b);
  }
  for (i = 0; i < 16; i++) {
    o[2*i] = t[i] & 0xff;
    o[2*i+1] = t[i]>>8;
  }
}

function unpack25519(o, n) {
  var i;
  for (i = 0; i < 16; i++) o[i] = n[2*i] + (n[2*i+1] << 8);
  o[15] &= 0x7fff;
}

function inv25519(o, i) {
  var c = gf();
  var a;
  for (a = 0; a < 16; a++) c[a] = i[a];
  for (a = 253; a >= 0; a--) {
    S(c, c);
    if(a !== 2 && a !== 4) M(c, c, i);
  }
  for (a = 0; a < 16; a++) o[a] = c[a];
}

function car25519(o) {
  var i, v, c = 1;
  for (i = 0; i < 16; i++) {
    v = o[i] + c + 65535;
    c = Math.floor(v / 65536);
    o[i] = v - c * 65536;
  }
  o[0] += c-1 + 37 * (c-1);
}

module.exports = {
  gf,
  A,
  Z,
  M,
  S,
  sel25519,
  pack25519,
  unpack25519,
  inv25519,
  gf0,
  gf1,
  _9,
  _121665,
  D,
  D2,
  X,
  Y,
  I
}

},{}],99:[function(require,module,exports){
/* eslint-disable camelcase */
const { sodium_malloc } = require('../memory')
const assert = require('nanoassert')

if (new Uint16Array([1])[0] !== 1) throw new Error('Big endian architecture is not supported.')

const crypto_core_hchacha20_OUTPUTBYTES = 32
const crypto_core_hchacha20_INPUTBYTES = 16
const crypto_core_hchacha20_KEYBYTES = 32
const crypto_core_hchacha20_CONSTBYTES = 16

function ROTL32 (x, b) {
  x &= 0xFFFFFFFF
  b &= 0xFFFFFFFF
  return (x << b) | (x >>> (32 - b))
}

function LOAD32_LE (src, offset) {
  assert(src instanceof Uint8Array, 'src not byte array')
  let w = src[offset]
  w |= src[offset + 1] << 8
  w |= src[offset + 2] << 16
  w |= src[offset + 3] << 24
  return w
}

function STORE32_LE (dest, int, offset) {
  assert(dest instanceof Uint8Array, 'dest not byte array')
  var mul = 1
  var i = 0
  dest[offset] = int & 0xFF // grab bottom byte
  while (++i < 4 && (mul *= 0x100)) {
    dest[offset + i] = (int / mul) & 0xFF
  }
}

function QUARTERROUND (l, A, B, C, D) {
  l[A] += l[B]
  l[D] = ROTL32(l[D] ^ l[A], 16)
  l[C] += l[D]
  l[B] = ROTL32(l[B] ^ l[C], 12)
  l[A] += l[B]
  l[D] = ROTL32(l[D] ^ l[A], 8)
  l[C] += l[D]
  l[B] = ROTL32(l[B] ^ l[C], 7)
}

function crypto_core_hchacha20 (out, _in, k, c) {
  assert(out instanceof Uint8Array && out.length === 32, 'out is not an array of 32 bytes')
  assert(k instanceof Uint8Array && k.length === 32, 'k is not an array of 32 bytes')
  assert(c === null || (c instanceof Uint8Array && c.length === 16), 'c is not null or an array of 16 bytes')

  let i = 0
  const x = new Uint32Array(16)
  if (!c) {
    x[0] = 0x61707865
    x[1] = 0x3320646E
    x[2] = 0x79622D32
    x[3] = 0x6B206574
  } else {
    x[0] = LOAD32_LE(c, 0)
    x[1] = LOAD32_LE(c, 4)
    x[2] = LOAD32_LE(c, 8)
    x[3] = LOAD32_LE(c, 12)
  }
  x[4] = LOAD32_LE(k, 0)
  x[5] = LOAD32_LE(k, 4)
  x[6] = LOAD32_LE(k, 8)
  x[7] = LOAD32_LE(k, 12)
  x[8] = LOAD32_LE(k, 16)
  x[9] = LOAD32_LE(k, 20)
  x[10] = LOAD32_LE(k, 24)
  x[11] = LOAD32_LE(k, 28)
  x[12] = LOAD32_LE(_in, 0)
  x[13] = LOAD32_LE(_in, 4)
  x[14] = LOAD32_LE(_in, 8)
  x[15] = LOAD32_LE(_in, 12)

  for (i = 0; i < 10; i++) {
    QUARTERROUND(x, 0, 4, 8, 12)
    QUARTERROUND(x, 1, 5, 9, 13)
    QUARTERROUND(x, 2, 6, 10, 14)
    QUARTERROUND(x, 3, 7, 11, 15)
    QUARTERROUND(x, 0, 5, 10, 15)
    QUARTERROUND(x, 1, 6, 11, 12)
    QUARTERROUND(x, 2, 7, 8, 13)
    QUARTERROUND(x, 3, 4, 9, 14)
  }

  STORE32_LE(out, x[0], 0)
  STORE32_LE(out, x[1], 4)
  STORE32_LE(out, x[2], 8)
  STORE32_LE(out, x[3], 12)
  STORE32_LE(out, x[12], 16)
  STORE32_LE(out, x[13], 20)
  STORE32_LE(out, x[14], 24)
  STORE32_LE(out, x[15], 28)

  return 0
}

function crypto_core_hchacha20_outputbytes () {
  return crypto_core_hchacha20_OUTPUTBYTES
}

function crypto_core_hchacha20_inputbytes () {
  return crypto_core_hchacha20_INPUTBYTES
}

function crypto_core_hchacha20_keybytes () {
  return crypto_core_hchacha20_KEYBYTES
}

function crypto_core_hchacha20_constbytes () {
  return crypto_core_hchacha20_CONSTBYTES
}

module.exports = {
  crypto_core_hchacha20_INPUTBYTES,
  LOAD32_LE,
  STORE32_LE,
  QUARTERROUND,
  crypto_core_hchacha20,
  crypto_core_hchacha20_outputbytes,
  crypto_core_hchacha20_inputbytes,
  crypto_core_hchacha20_keybytes,
  crypto_core_hchacha20_constbytes
}

},{"../memory":101,"nanoassert":51}],100:[function(require,module,exports){
/*
* Port of Andrew Moon's Poly1305-donna-16. Public domain.
* https://github.com/floodyberry/poly1305-donna
*/

if (new Uint16Array([1])[0] !== 1) throw new Error('Big endian architecture is not supported.')

var poly1305 = function(key) {
  this.buffer = new Uint8Array(16);
  this.r = new Uint16Array(10);
  this.h = new Uint16Array(10);
  this.pad = new Uint16Array(8);
  this.leftover = 0;
  this.fin = 0;

  var t0, t1, t2, t3, t4, t5, t6, t7;

  t0 = key[ 0] & 0xff | (key[ 1] & 0xff) << 8; this.r[0] = ( t0                     ) & 0x1fff;
  t1 = key[ 2] & 0xff | (key[ 3] & 0xff) << 8; this.r[1] = ((t0 >>> 13) | (t1 <<  3)) & 0x1fff;
  t2 = key[ 4] & 0xff | (key[ 5] & 0xff) << 8; this.r[2] = ((t1 >>> 10) | (t2 <<  6)) & 0x1f03;
  t3 = key[ 6] & 0xff | (key[ 7] & 0xff) << 8; this.r[3] = ((t2 >>>  7) | (t3 <<  9)) & 0x1fff;
  t4 = key[ 8] & 0xff | (key[ 9] & 0xff) << 8; this.r[4] = ((t3 >>>  4) | (t4 << 12)) & 0x00ff;
  this.r[5] = ((t4 >>>  1)) & 0x1ffe;
  t5 = key[10] & 0xff | (key[11] & 0xff) << 8; this.r[6] = ((t4 >>> 14) | (t5 <<  2)) & 0x1fff;
  t6 = key[12] & 0xff | (key[13] & 0xff) << 8; this.r[7] = ((t5 >>> 11) | (t6 <<  5)) & 0x1f81;
  t7 = key[14] & 0xff | (key[15] & 0xff) << 8; this.r[8] = ((t6 >>>  8) | (t7 <<  8)) & 0x1fff;
  this.r[9] = ((t7 >>>  5)) & 0x007f;

  this.pad[0] = key[16] & 0xff | (key[17] & 0xff) << 8;
  this.pad[1] = key[18] & 0xff | (key[19] & 0xff) << 8;
  this.pad[2] = key[20] & 0xff | (key[21] & 0xff) << 8;
  this.pad[3] = key[22] & 0xff | (key[23] & 0xff) << 8;
  this.pad[4] = key[24] & 0xff | (key[25] & 0xff) << 8;
  this.pad[5] = key[26] & 0xff | (key[27] & 0xff) << 8;
  this.pad[6] = key[28] & 0xff | (key[29] & 0xff) << 8;
  this.pad[7] = key[30] & 0xff | (key[31] & 0xff) << 8;
};

poly1305.prototype.blocks = function(m, mpos, bytes) {
  var hibit = this.fin ? 0 : (1 << 11);
  var t0, t1, t2, t3, t4, t5, t6, t7, c;
  var d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;

  var h0 = this.h[0],
      h1 = this.h[1],
      h2 = this.h[2],
      h3 = this.h[3],
      h4 = this.h[4],
      h5 = this.h[5],
      h6 = this.h[6],
      h7 = this.h[7],
      h8 = this.h[8],
      h9 = this.h[9];

  var r0 = this.r[0],
      r1 = this.r[1],
      r2 = this.r[2],
      r3 = this.r[3],
      r4 = this.r[4],
      r5 = this.r[5],
      r6 = this.r[6],
      r7 = this.r[7],
      r8 = this.r[8],
      r9 = this.r[9];

  while (bytes >= 16) {
    t0 = m[mpos+ 0] & 0xff | (m[mpos+ 1] & 0xff) << 8; h0 += ( t0                     ) & 0x1fff;
    t1 = m[mpos+ 2] & 0xff | (m[mpos+ 3] & 0xff) << 8; h1 += ((t0 >>> 13) | (t1 <<  3)) & 0x1fff;
    t2 = m[mpos+ 4] & 0xff | (m[mpos+ 5] & 0xff) << 8; h2 += ((t1 >>> 10) | (t2 <<  6)) & 0x1fff;
    t3 = m[mpos+ 6] & 0xff | (m[mpos+ 7] & 0xff) << 8; h3 += ((t2 >>>  7) | (t3 <<  9)) & 0x1fff;
    t4 = m[mpos+ 8] & 0xff | (m[mpos+ 9] & 0xff) << 8; h4 += ((t3 >>>  4) | (t4 << 12)) & 0x1fff;
    h5 += ((t4 >>>  1)) & 0x1fff;
    t5 = m[mpos+10] & 0xff | (m[mpos+11] & 0xff) << 8; h6 += ((t4 >>> 14) | (t5 <<  2)) & 0x1fff;
    t6 = m[mpos+12] & 0xff | (m[mpos+13] & 0xff) << 8; h7 += ((t5 >>> 11) | (t6 <<  5)) & 0x1fff;
    t7 = m[mpos+14] & 0xff | (m[mpos+15] & 0xff) << 8; h8 += ((t6 >>>  8) | (t7 <<  8)) & 0x1fff;
    h9 += ((t7 >>> 5)) | hibit;

    c = 0;

    d0 = c;
    d0 += h0 * r0;
    d0 += h1 * (5 * r9);
    d0 += h2 * (5 * r8);
    d0 += h3 * (5 * r7);
    d0 += h4 * (5 * r6);
    c = (d0 >>> 13); d0 &= 0x1fff;
    d0 += h5 * (5 * r5);
    d0 += h6 * (5 * r4);
    d0 += h7 * (5 * r3);
    d0 += h8 * (5 * r2);
    d0 += h9 * (5 * r1);
    c += (d0 >>> 13); d0 &= 0x1fff;

    d1 = c;
    d1 += h0 * r1;
    d1 += h1 * r0;
    d1 += h2 * (5 * r9);
    d1 += h3 * (5 * r8);
    d1 += h4 * (5 * r7);
    c = (d1 >>> 13); d1 &= 0x1fff;
    d1 += h5 * (5 * r6);
    d1 += h6 * (5 * r5);
    d1 += h7 * (5 * r4);
    d1 += h8 * (5 * r3);
    d1 += h9 * (5 * r2);
    c += (d1 >>> 13); d1 &= 0x1fff;

    d2 = c;
    d2 += h0 * r2;
    d2 += h1 * r1;
    d2 += h2 * r0;
    d2 += h3 * (5 * r9);
    d2 += h4 * (5 * r8);
    c = (d2 >>> 13); d2 &= 0x1fff;
    d2 += h5 * (5 * r7);
    d2 += h6 * (5 * r6);
    d2 += h7 * (5 * r5);
    d2 += h8 * (5 * r4);
    d2 += h9 * (5 * r3);
    c += (d2 >>> 13); d2 &= 0x1fff;

    d3 = c;
    d3 += h0 * r3;
    d3 += h1 * r2;
    d3 += h2 * r1;
    d3 += h3 * r0;
    d3 += h4 * (5 * r9);
    c = (d3 >>> 13); d3 &= 0x1fff;
    d3 += h5 * (5 * r8);
    d3 += h6 * (5 * r7);
    d3 += h7 * (5 * r6);
    d3 += h8 * (5 * r5);
    d3 += h9 * (5 * r4);
    c += (d3 >>> 13); d3 &= 0x1fff;

    d4 = c;
    d4 += h0 * r4;
    d4 += h1 * r3;
    d4 += h2 * r2;
    d4 += h3 * r1;
    d4 += h4 * r0;
    c = (d4 >>> 13); d4 &= 0x1fff;
    d4 += h5 * (5 * r9);
    d4 += h6 * (5 * r8);
    d4 += h7 * (5 * r7);
    d4 += h8 * (5 * r6);
    d4 += h9 * (5 * r5);
    c += (d4 >>> 13); d4 &= 0x1fff;

    d5 = c;
    d5 += h0 * r5;
    d5 += h1 * r4;
    d5 += h2 * r3;
    d5 += h3 * r2;
    d5 += h4 * r1;
    c = (d5 >>> 13); d5 &= 0x1fff;
    d5 += h5 * r0;
    d5 += h6 * (5 * r9);
    d5 += h7 * (5 * r8);
    d5 += h8 * (5 * r7);
    d5 += h9 * (5 * r6);
    c += (d5 >>> 13); d5 &= 0x1fff;

    d6 = c;
    d6 += h0 * r6;
    d6 += h1 * r5;
    d6 += h2 * r4;
    d6 += h3 * r3;
    d6 += h4 * r2;
    c = (d6 >>> 13); d6 &= 0x1fff;
    d6 += h5 * r1;
    d6 += h6 * r0;
    d6 += h7 * (5 * r9);
    d6 += h8 * (5 * r8);
    d6 += h9 * (5 * r7);
    c += (d6 >>> 13); d6 &= 0x1fff;

    d7 = c;
    d7 += h0 * r7;
    d7 += h1 * r6;
    d7 += h2 * r5;
    d7 += h3 * r4;
    d7 += h4 * r3;
    c = (d7 >>> 13); d7 &= 0x1fff;
    d7 += h5 * r2;
    d7 += h6 * r1;
    d7 += h7 * r0;
    d7 += h8 * (5 * r9);
    d7 += h9 * (5 * r8);
    c += (d7 >>> 13); d7 &= 0x1fff;

    d8 = c;
    d8 += h0 * r8;
    d8 += h1 * r7;
    d8 += h2 * r6;
    d8 += h3 * r5;
    d8 += h4 * r4;
    c = (d8 >>> 13); d8 &= 0x1fff;
    d8 += h5 * r3;
    d8 += h6 * r2;
    d8 += h7 * r1;
    d8 += h8 * r0;
    d8 += h9 * (5 * r9);
    c += (d8 >>> 13); d8 &= 0x1fff;

    d9 = c;
    d9 += h0 * r9;
    d9 += h1 * r8;
    d9 += h2 * r7;
    d9 += h3 * r6;
    d9 += h4 * r5;
    c = (d9 >>> 13); d9 &= 0x1fff;
    d9 += h5 * r4;
    d9 += h6 * r3;
    d9 += h7 * r2;
    d9 += h8 * r1;
    d9 += h9 * r0;
    c += (d9 >>> 13); d9 &= 0x1fff;

    c = (((c << 2) + c)) | 0;
    c = (c + d0) | 0;
    d0 = c & 0x1fff;
    c = (c >>> 13);
    d1 += c;

    h0 = d0;
    h1 = d1;
    h2 = d2;
    h3 = d3;
    h4 = d4;
    h5 = d5;
    h6 = d6;
    h7 = d7;
    h8 = d8;
    h9 = d9;

    mpos += 16;
    bytes -= 16;
  }
  this.h[0] = h0;
  this.h[1] = h1;
  this.h[2] = h2;
  this.h[3] = h3;
  this.h[4] = h4;
  this.h[5] = h5;
  this.h[6] = h6;
  this.h[7] = h7;
  this.h[8] = h8;
  this.h[9] = h9;
};

poly1305.prototype.finish = function(mac, macpos) {
  var g = new Uint16Array(10);
  var c, mask, f, i;

  if (this.leftover) {
    i = this.leftover;
    this.buffer[i++] = 1;
    for (; i < 16; i++) this.buffer[i] = 0;
    this.fin = 1;
    this.blocks(this.buffer, 0, 16);
  }

  c = this.h[1] >>> 13;
  this.h[1] &= 0x1fff;
  for (i = 2; i < 10; i++) {
    this.h[i] += c;
    c = this.h[i] >>> 13;
    this.h[i] &= 0x1fff;
  }
  this.h[0] += (c * 5);
  c = this.h[0] >>> 13;
  this.h[0] &= 0x1fff;
  this.h[1] += c;
  c = this.h[1] >>> 13;
  this.h[1] &= 0x1fff;
  this.h[2] += c;

  g[0] = this.h[0] + 5;
  c = g[0] >>> 13;
  g[0] &= 0x1fff;
  for (i = 1; i < 10; i++) {
    g[i] = this.h[i] + c;
    c = g[i] >>> 13;
    g[i] &= 0x1fff;
  }
  g[9] -= (1 << 13);

  mask = (c ^ 1) - 1;
  for (i = 0; i < 10; i++) g[i] &= mask;
  mask = ~mask;
  for (i = 0; i < 10; i++) this.h[i] = (this.h[i] & mask) | g[i];

  this.h[0] = ((this.h[0]       ) | (this.h[1] << 13)                    ) & 0xffff;
  this.h[1] = ((this.h[1] >>>  3) | (this.h[2] << 10)                    ) & 0xffff;
  this.h[2] = ((this.h[2] >>>  6) | (this.h[3] <<  7)                    ) & 0xffff;
  this.h[3] = ((this.h[3] >>>  9) | (this.h[4] <<  4)                    ) & 0xffff;
  this.h[4] = ((this.h[4] >>> 12) | (this.h[5] <<  1) | (this.h[6] << 14)) & 0xffff;
  this.h[5] = ((this.h[6] >>>  2) | (this.h[7] << 11)                    ) & 0xffff;
  this.h[6] = ((this.h[7] >>>  5) | (this.h[8] <<  8)                    ) & 0xffff;
  this.h[7] = ((this.h[8] >>>  8) | (this.h[9] <<  5)                    ) & 0xffff;

  f = this.h[0] + this.pad[0];
  this.h[0] = f & 0xffff;
  for (i = 1; i < 8; i++) {
    f = (((this.h[i] + this.pad[i]) | 0) + (f >>> 16)) | 0;
    this.h[i] = f & 0xffff;
  }

  mac[macpos+ 0] = (this.h[0] >>> 0) & 0xff;
  mac[macpos+ 1] = (this.h[0] >>> 8) & 0xff;
  mac[macpos+ 2] = (this.h[1] >>> 0) & 0xff;
  mac[macpos+ 3] = (this.h[1] >>> 8) & 0xff;
  mac[macpos+ 4] = (this.h[2] >>> 0) & 0xff;
  mac[macpos+ 5] = (this.h[2] >>> 8) & 0xff;
  mac[macpos+ 6] = (this.h[3] >>> 0) & 0xff;
  mac[macpos+ 7] = (this.h[3] >>> 8) & 0xff;
  mac[macpos+ 8] = (this.h[4] >>> 0) & 0xff;
  mac[macpos+ 9] = (this.h[4] >>> 8) & 0xff;
  mac[macpos+10] = (this.h[5] >>> 0) & 0xff;
  mac[macpos+11] = (this.h[5] >>> 8) & 0xff;
  mac[macpos+12] = (this.h[6] >>> 0) & 0xff;
  mac[macpos+13] = (this.h[6] >>> 8) & 0xff;
  mac[macpos+14] = (this.h[7] >>> 0) & 0xff;
  mac[macpos+15] = (this.h[7] >>> 8) & 0xff;
};

poly1305.prototype.update = function(m, mpos, bytes) {
  var i, want;

  if (this.leftover) {
    want = (16 - this.leftover);
    if (want > bytes)
      want = bytes;
    for (i = 0; i < want; i++)
      this.buffer[this.leftover + i] = m[mpos+i];
    bytes -= want;
    mpos += want;
    this.leftover += want;
    if (this.leftover < 16)
      return;
    this.blocks(this.buffer, 0, 16);
    this.leftover = 0;
  }

  if (bytes >= 16) {
    want = bytes - (bytes % 16);
    this.blocks(m, mpos, want);
    mpos += want;
    bytes -= want;
  }

  if (bytes) {
    for (i = 0; i < bytes; i++)
      this.buffer[this.leftover + i] = m[mpos+i];
    this.leftover += bytes;
  }
};

module.exports = poly1305

},{}],101:[function(require,module,exports){
/* eslint-disable camelcase */

function sodium_malloc (n) {
  return new Uint8Array(n)
}

function sodium_free (n) {
  sodium_memzero(n)
  loadSink().port1.postMessage(n.buffer, [n.buffer])
}

function sodium_memzero (arr) {
  arr.fill(0)
}

var sink

function loadSink () {
  if (sink) return sink
  var MessageChannel = globalThis.MessageChannel
  if (MessageChannel == null) ({ MessageChannel } = require('worker' + '_threads'))
  sink = new MessageChannel()
  return sink
}

module.exports = {
  sodium_malloc,
  sodium_free,
  sodium_memzero
}

},{}],102:[function(require,module,exports){
var assert = require('nanoassert')

var randombytes = (function () {
  var QUOTA = 65536 // limit for QuotaExceededException
  var crypto = globalThis.crypto || globalThis.msCrypto

  function browserBytes (out, n) {
    for (let i = 0; i < n; i += QUOTA) {
      crypto.getRandomValues(new Uint8Array(out.buffer, i + out.byteOffset, Math.min(n - i, QUOTA)))
    }
  }

  function nodeBytes (out, n) {
    new Uint8Array(out.buffer, out.byteOffset, n).set(crypto.randomBytes(n))
  }

  function noImpl () {
    throw new Error('No secure random number generator available')
  }

  if (crypto && crypto.getRandomValues) return browserBytes

  if (require != null) {
    // Node.js. Bust Browserify
    crypto = require('cry' + 'pto')
    if (crypto && crypto.randomBytes) return nodeBytes
  }

  return noImpl
})()

// Make non enumerable as this is an internal function
Object.defineProperty(module.exports, 'randombytes', {
  value: randombytes
})

module.exports.randombytes_buf = function (out) {
  assert(out, 'out must be given')
  randombytes(out, out.byteLength)
}

},{"nanoassert":51}],103:[function(require,module,exports){
const sodium = require('sodium-universal')
const b4a = require('b4a')

const ABYTES = sodium.crypto_secretstream_xchacha20poly1305_ABYTES
const TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
const TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
const STATEBYTES = sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES
const HEADERBYTES = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES
const KEYBYTES = sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES
const TAG_FINAL_BYTE = b4a.isBuffer(TAG_FINAL) ? TAG_FINAL[0] : TAG_FINAL

const EMPTY = b4a.alloc(0)
const TAG = b4a.alloc(1)

class Push {
  constructor (key, state = b4a.allocUnsafe(STATEBYTES), header = b4a.allocUnsafe(HEADERBYTES)) {
    if (!TAG_FINAL) throw new Error('JavaScript sodium version needs to support crypto_secretstream_xchacha20poly')

    this.key = key
    this.state = state
    this.header = header

    sodium.crypto_secretstream_xchacha20poly1305_init_push(this.state, this.header, this.key)
  }

  next (message, cipher = b4a.allocUnsafe(message.byteLength + ABYTES)) {
    sodium.crypto_secretstream_xchacha20poly1305_push(this.state, cipher, message, null, TAG_MESSAGE)
    return cipher
  }

  final (message = EMPTY, cipher = b4a.allocUnsafe(ABYTES)) {
    sodium.crypto_secretstream_xchacha20poly1305_push(this.state, cipher, message, null, TAG_FINAL)
    return cipher
  }
}

class Pull {
  constructor (key, state = b4a.allocUnsafe(STATEBYTES)) {
    if (!TAG_FINAL) throw new Error('JavaScript sodium version needs to support crypto_secretstream_xchacha20poly')

    this.key = key
    this.state = state
    this.final = false
  }

  init (header) {
    sodium.crypto_secretstream_xchacha20poly1305_init_pull(this.state, header, this.key)
  }

  next (cipher, message = b4a.allocUnsafe(cipher.byteLength - ABYTES)) {
    sodium.crypto_secretstream_xchacha20poly1305_pull(this.state, message, TAG, cipher, null)
    this.final = TAG[0] === TAG_FINAL_BYTE
    return message
  }
}

function keygen (buf = b4a.alloc(KEYBYTES)) {
  sodium.crypto_secretstream_xchacha20poly1305_keygen(buf)
  return buf
}

module.exports = {
  keygen,
  KEYBYTES,
  ABYTES,
  STATEBYTES,
  HEADERBYTES,
  Push,
  Pull
}

},{"b4a":4,"sodium-universal":122}],104:[function(require,module,exports){
arguments[4][79][0].apply(exports,arguments)
},{"./crypto_stream_chacha20":119,"./crypto_verify":120,"./internal/poly1305":125,"dup":79,"nanoassert":51}],105:[function(require,module,exports){
arguments[4][80][0].apply(exports,arguments)
},{"./crypto_verify":120,"dup":80,"nanoassert":51,"sha512-universal":70}],106:[function(require,module,exports){
arguments[4][81][0].apply(exports,arguments)
},{"./crypto_generichash":107,"./crypto_hash":108,"./crypto_scalarmult":113,"./crypto_secretbox":114,"./crypto_stream":118,"./randombytes":127,"dup":81,"nanoassert":51,"xsalsa20":131}],107:[function(require,module,exports){
arguments[4][82][0].apply(exports,arguments)
},{"blake2b":13,"dup":82}],108:[function(require,module,exports){
arguments[4][83][0].apply(exports,arguments)
},{"dup":83,"nanoassert":51,"sha512-universal":70}],109:[function(require,module,exports){
arguments[4][84][0].apply(exports,arguments)
},{"dup":84,"nanoassert":51,"sha256-universal":66}],110:[function(require,module,exports){
arguments[4][85][0].apply(exports,arguments)
},{"./randombytes":127,"blake2b":13,"dup":85,"nanoassert":51}],111:[function(require,module,exports){
arguments[4][86][0].apply(exports,arguments)
},{"./crypto_generichash":107,"./crypto_scalarmult":113,"./randombytes":127,"dup":86,"nanoassert":51}],112:[function(require,module,exports){
arguments[4][87][0].apply(exports,arguments)
},{"./crypto_verify":120,"./internal/poly1305":125,"dup":87,"nanoassert":51}],113:[function(require,module,exports){
arguments[4][88][0].apply(exports,arguments)
},{"./internal/ed25519":123,"dup":88}],114:[function(require,module,exports){
arguments[4][89][0].apply(exports,arguments)
},{"./crypto_onetimeauth":112,"./crypto_stream":118,"dup":89,"nanoassert":51}],115:[function(require,module,exports){
arguments[4][90][0].apply(exports,arguments)
},{"./crypto_stream_chacha20":119,"./helpers":121,"./internal/hchacha20":124,"./internal/poly1305":125,"./randombytes":127,"dup":90,"nanoassert":51}],116:[function(require,module,exports){
arguments[4][91][0].apply(exports,arguments)
},{"dup":91,"siphash24":77}],117:[function(require,module,exports){
arguments[4][92][0].apply(exports,arguments)
},{"./crypto_hash":108,"./crypto_hash.js":108,"./crypto_scalarmult.js":113,"./crypto_verify":120,"./internal/ed25519":123,"./randombytes":127,"dup":92,"nanoassert":51}],118:[function(require,module,exports){
arguments[4][93][0].apply(exports,arguments)
},{"dup":93,"xsalsa20":131}],119:[function(require,module,exports){
arguments[4][94][0].apply(exports,arguments)
},{"chacha20-universal":14,"dup":94,"nanoassert":51}],120:[function(require,module,exports){
arguments[4][95][0].apply(exports,arguments)
},{"dup":95}],121:[function(require,module,exports){
arguments[4][96][0].apply(exports,arguments)
},{"./crypto_verify":120,"dup":96,"nanoassert":51}],122:[function(require,module,exports){
arguments[4][97][0].apply(exports,arguments)
},{"./crypto_aead":104,"./crypto_auth":105,"./crypto_box":106,"./crypto_generichash":107,"./crypto_hash":108,"./crypto_hash_sha256":109,"./crypto_kdf":110,"./crypto_kx":111,"./crypto_onetimeauth":112,"./crypto_scalarmult":113,"./crypto_secretbox":114,"./crypto_secretstream":115,"./crypto_shorthash":116,"./crypto_sign":117,"./crypto_stream":118,"./crypto_stream_chacha20":119,"./crypto_verify":120,"./helpers":121,"./memory":126,"./randombytes":127,"dup":97}],123:[function(require,module,exports){
arguments[4][98][0].apply(exports,arguments)
},{"dup":98}],124:[function(require,module,exports){
arguments[4][99][0].apply(exports,arguments)
},{"../memory":126,"dup":99,"nanoassert":51}],125:[function(require,module,exports){
arguments[4][100][0].apply(exports,arguments)
},{"dup":100}],126:[function(require,module,exports){
arguments[4][101][0].apply(exports,arguments)
},{"dup":101}],127:[function(require,module,exports){
arguments[4][102][0].apply(exports,arguments)
},{"dup":102,"nanoassert":51}],128:[function(require,module,exports){
const { EventEmitter } = require('events')
const STREAM_DESTROYED = new Error('Stream was destroyed')
const PREMATURE_CLOSE = new Error('Premature close')

const queueTick = require('queue-tick')
const FIFO = require('fast-fifo')

/* eslint-disable no-multi-spaces */

// 27 bits used total (4 from shared, 13 from read, and 10 from write)
const MAX = ((1 << 27) - 1)

// Shared state
const OPENING       = 0b0001
const PREDESTROYING = 0b0010
const DESTROYING    = 0b0100
const DESTROYED     = 0b1000

const NOT_OPENING = MAX ^ OPENING
const NOT_PREDESTROYING = MAX ^ PREDESTROYING

// Read state (4 bit offset from shared state)
const READ_ACTIVE           = 0b0000000000001 << 4
const READ_UPDATING         = 0b0000000000010 << 4
const READ_PRIMARY          = 0b0000000000100 << 4
const READ_QUEUED           = 0b0000000001000 << 4
const READ_RESUMED          = 0b0000000010000 << 4
const READ_PIPE_DRAINED     = 0b0000000100000 << 4
const READ_ENDING           = 0b0000001000000 << 4
const READ_EMIT_DATA        = 0b0000010000000 << 4
const READ_EMIT_READABLE    = 0b0000100000000 << 4
const READ_EMITTED_READABLE = 0b0001000000000 << 4
const READ_DONE             = 0b0010000000000 << 4
const READ_NEXT_TICK        = 0b0100000000000 << 4
const READ_NEEDS_PUSH       = 0b1000000000000 << 4

// Combined read state
const READ_FLOWING = READ_RESUMED | READ_PIPE_DRAINED
const READ_ACTIVE_AND_NEEDS_PUSH = READ_ACTIVE | READ_NEEDS_PUSH
const READ_PRIMARY_AND_ACTIVE = READ_PRIMARY | READ_ACTIVE
const READ_EMIT_READABLE_AND_QUEUED = READ_EMIT_READABLE | READ_QUEUED

const READ_NOT_ACTIVE             = MAX ^ READ_ACTIVE
const READ_NON_PRIMARY            = MAX ^ READ_PRIMARY
const READ_NON_PRIMARY_AND_PUSHED = MAX ^ (READ_PRIMARY | READ_NEEDS_PUSH)
const READ_PUSHED                 = MAX ^ READ_NEEDS_PUSH
const READ_PAUSED                 = MAX ^ READ_RESUMED
const READ_NOT_QUEUED             = MAX ^ (READ_QUEUED | READ_EMITTED_READABLE)
const READ_NOT_ENDING             = MAX ^ READ_ENDING
const READ_PIPE_NOT_DRAINED       = MAX ^ READ_FLOWING
const READ_NOT_NEXT_TICK          = MAX ^ READ_NEXT_TICK
const READ_NOT_UPDATING           = MAX ^ READ_UPDATING

// Write state (17 bit offset, 4 bit offset from shared state and 13 from read state)
const WRITE_ACTIVE     = 0b0000000001 << 17
const WRITE_UPDATING   = 0b0000000010 << 17
const WRITE_PRIMARY    = 0b0000000100 << 17
const WRITE_QUEUED     = 0b0000001000 << 17
const WRITE_UNDRAINED  = 0b0000010000 << 17
const WRITE_DONE       = 0b0000100000 << 17
const WRITE_EMIT_DRAIN = 0b0001000000 << 17
const WRITE_NEXT_TICK  = 0b0010000000 << 17
const WRITE_WRITING    = 0b0100000000 << 17
const WRITE_FINISHING  = 0b1000000000 << 17

const WRITE_NOT_ACTIVE    = MAX ^ (WRITE_ACTIVE | WRITE_WRITING)
const WRITE_NON_PRIMARY   = MAX ^ WRITE_PRIMARY
const WRITE_NOT_FINISHING = MAX ^ WRITE_FINISHING
const WRITE_DRAINED       = MAX ^ WRITE_UNDRAINED
const WRITE_NOT_QUEUED    = MAX ^ WRITE_QUEUED
const WRITE_NOT_NEXT_TICK = MAX ^ WRITE_NEXT_TICK
const WRITE_NOT_UPDATING  = MAX ^ WRITE_UPDATING

// Combined shared state
const ACTIVE = READ_ACTIVE | WRITE_ACTIVE
const NOT_ACTIVE = MAX ^ ACTIVE
const DONE = READ_DONE | WRITE_DONE
const DESTROY_STATUS = DESTROYING | DESTROYED | PREDESTROYING
const OPEN_STATUS = DESTROY_STATUS | OPENING
const AUTO_DESTROY = DESTROY_STATUS | DONE
const NON_PRIMARY = WRITE_NON_PRIMARY & READ_NON_PRIMARY
const ACTIVE_OR_TICKING = WRITE_NEXT_TICK | READ_NEXT_TICK
const TICKING = ACTIVE_OR_TICKING & NOT_ACTIVE
const IS_OPENING = OPEN_STATUS | TICKING

// Combined shared state and read state
const READ_PRIMARY_STATUS = OPEN_STATUS | READ_ENDING | READ_DONE
const READ_STATUS = OPEN_STATUS | READ_DONE | READ_QUEUED
const READ_ENDING_STATUS = OPEN_STATUS | READ_ENDING | READ_QUEUED
const READ_READABLE_STATUS = OPEN_STATUS | READ_EMIT_READABLE | READ_QUEUED | READ_EMITTED_READABLE
const SHOULD_NOT_READ = OPEN_STATUS | READ_ACTIVE | READ_ENDING | READ_DONE | READ_NEEDS_PUSH
const READ_BACKPRESSURE_STATUS = DESTROY_STATUS | READ_ENDING | READ_DONE
const READ_UPDATE_SYNC_STATUS = READ_UPDATING | OPEN_STATUS | READ_NEXT_TICK | READ_PRIMARY

// Combined write state
const WRITE_PRIMARY_STATUS = OPEN_STATUS | WRITE_FINISHING | WRITE_DONE
const WRITE_QUEUED_AND_UNDRAINED = WRITE_QUEUED | WRITE_UNDRAINED
const WRITE_QUEUED_AND_ACTIVE = WRITE_QUEUED | WRITE_ACTIVE
const WRITE_DRAIN_STATUS = WRITE_QUEUED | WRITE_UNDRAINED | OPEN_STATUS | WRITE_ACTIVE
const WRITE_STATUS = OPEN_STATUS | WRITE_ACTIVE | WRITE_QUEUED
const WRITE_PRIMARY_AND_ACTIVE = WRITE_PRIMARY | WRITE_ACTIVE
const WRITE_ACTIVE_AND_WRITING = WRITE_ACTIVE | WRITE_WRITING
const WRITE_FINISHING_STATUS = OPEN_STATUS | WRITE_FINISHING | WRITE_QUEUED_AND_ACTIVE | WRITE_DONE
const WRITE_BACKPRESSURE_STATUS = WRITE_UNDRAINED | DESTROY_STATUS | WRITE_FINISHING | WRITE_DONE
const WRITE_UPDATE_SYNC_STATUS = WRITE_UPDATING | OPEN_STATUS | WRITE_NEXT_TICK | WRITE_PRIMARY

const asyncIterator = Symbol.asyncIterator || Symbol('asyncIterator')

class WritableState {
  constructor (stream, { highWaterMark = 16384, map = null, mapWritable, byteLength, byteLengthWritable } = {}) {
    this.stream = stream
    this.queue = new FIFO()
    this.highWaterMark = highWaterMark
    this.buffered = 0
    this.error = null
    this.pipeline = null
    this.drains = null // if we add more seldomly used helpers we might them into a subobject so its a single ptr
    this.byteLength = byteLengthWritable || byteLength || defaultByteLength
    this.map = mapWritable || map
    this.afterWrite = afterWrite.bind(this)
    this.afterUpdateNextTick = updateWriteNT.bind(this)
  }

  get ended () {
    return (this.stream._duplexState & WRITE_DONE) !== 0
  }

  push (data) {
    if (this.map !== null) data = this.map(data)

    this.buffered += this.byteLength(data)
    this.queue.push(data)

    if (this.buffered < this.highWaterMark) {
      this.stream._duplexState |= WRITE_QUEUED
      return true
    }

    this.stream._duplexState |= WRITE_QUEUED_AND_UNDRAINED
    return false
  }

  shift () {
    const data = this.queue.shift()

    this.buffered -= this.byteLength(data)
    if (this.buffered === 0) this.stream._duplexState &= WRITE_NOT_QUEUED

    return data
  }

  end (data) {
    if (typeof data === 'function') this.stream.once('finish', data)
    else if (data !== undefined && data !== null) this.push(data)
    this.stream._duplexState = (this.stream._duplexState | WRITE_FINISHING) & WRITE_NON_PRIMARY
  }

  autoBatch (data, cb) {
    const buffer = []
    const stream = this.stream

    buffer.push(data)
    while ((stream._duplexState & WRITE_STATUS) === WRITE_QUEUED_AND_ACTIVE) {
      buffer.push(stream._writableState.shift())
    }

    if ((stream._duplexState & OPEN_STATUS) !== 0) return cb(null)
    stream._writev(buffer, cb)
  }

  update () {
    const stream = this.stream

    stream._duplexState |= WRITE_UPDATING

    do {
      while ((stream._duplexState & WRITE_STATUS) === WRITE_QUEUED) {
        const data = this.shift()
        stream._duplexState |= WRITE_ACTIVE_AND_WRITING
        stream._write(data, this.afterWrite)
      }

      if ((stream._duplexState & WRITE_PRIMARY_AND_ACTIVE) === 0) this.updateNonPrimary()
    } while (this.continueUpdate() === true)

    stream._duplexState &= WRITE_NOT_UPDATING
  }

  updateNonPrimary () {
    const stream = this.stream

    if ((stream._duplexState & WRITE_FINISHING_STATUS) === WRITE_FINISHING) {
      stream._duplexState = (stream._duplexState | WRITE_ACTIVE) & WRITE_NOT_FINISHING
      stream._final(afterFinal.bind(this))
      return
    }

    if ((stream._duplexState & DESTROY_STATUS) === DESTROYING) {
      if ((stream._duplexState & ACTIVE_OR_TICKING) === 0) {
        stream._duplexState |= ACTIVE
        stream._destroy(afterDestroy.bind(this))
      }
      return
    }

    if ((stream._duplexState & IS_OPENING) === OPENING) {
      stream._duplexState = (stream._duplexState | ACTIVE) & NOT_OPENING
      stream._open(afterOpen.bind(this))
    }
  }

  continueUpdate () {
    if ((this.stream._duplexState & WRITE_NEXT_TICK) === 0) return false
    this.stream._duplexState &= WRITE_NOT_NEXT_TICK
    return true
  }

  updateCallback () {
    if ((this.stream._duplexState & WRITE_UPDATE_SYNC_STATUS) === WRITE_PRIMARY) this.update()
    else this.updateNextTick()
  }

  updateNextTick () {
    if ((this.stream._duplexState & WRITE_NEXT_TICK) !== 0) return
    this.stream._duplexState |= WRITE_NEXT_TICK
    if ((this.stream._duplexState & WRITE_UPDATING) === 0) queueTick(this.afterUpdateNextTick)
  }
}

class ReadableState {
  constructor (stream, { highWaterMark = 16384, map = null, mapReadable, byteLength, byteLengthReadable } = {}) {
    this.stream = stream
    this.queue = new FIFO()
    this.highWaterMark = highWaterMark
    this.buffered = 0
    this.error = null
    this.pipeline = null
    this.byteLength = byteLengthReadable || byteLength || defaultByteLength
    this.map = mapReadable || map
    this.pipeTo = null
    this.afterRead = afterRead.bind(this)
    this.afterUpdateNextTick = updateReadNT.bind(this)
  }

  get ended () {
    return (this.stream._duplexState & READ_DONE) !== 0
  }

  pipe (pipeTo, cb) {
    if (this.pipeTo !== null) throw new Error('Can only pipe to one destination')
    if (typeof cb !== 'function') cb = null

    this.stream._duplexState |= READ_PIPE_DRAINED
    this.pipeTo = pipeTo
    this.pipeline = new Pipeline(this.stream, pipeTo, cb)

    if (cb) this.stream.on('error', noop) // We already error handle this so supress crashes

    if (isStreamx(pipeTo)) {
      pipeTo._writableState.pipeline = this.pipeline
      if (cb) pipeTo.on('error', noop) // We already error handle this so supress crashes
      pipeTo.on('finish', this.pipeline.finished.bind(this.pipeline)) // TODO: just call finished from pipeTo itself
    } else {
      const onerror = this.pipeline.done.bind(this.pipeline, pipeTo)
      const onclose = this.pipeline.done.bind(this.pipeline, pipeTo, null) // onclose has a weird bool arg
      pipeTo.on('error', onerror)
      pipeTo.on('close', onclose)
      pipeTo.on('finish', this.pipeline.finished.bind(this.pipeline))
    }

    pipeTo.on('drain', afterDrain.bind(this))
    this.stream.emit('piping', pipeTo)
    pipeTo.emit('pipe', this.stream)
  }

  push (data) {
    const stream = this.stream

    if (data === null) {
      this.highWaterMark = 0
      stream._duplexState = (stream._duplexState | READ_ENDING) & READ_NON_PRIMARY_AND_PUSHED
      return false
    }

    if (this.map !== null) data = this.map(data)
    this.buffered += this.byteLength(data)
    this.queue.push(data)

    stream._duplexState = (stream._duplexState | READ_QUEUED) & READ_PUSHED

    return this.buffered < this.highWaterMark
  }

  shift () {
    const data = this.queue.shift()

    this.buffered -= this.byteLength(data)
    if (this.buffered === 0) this.stream._duplexState &= READ_NOT_QUEUED
    return data
  }

  unshift (data) {
    const pending = [this.map !== null ? this.map(data) : data]
    while (this.buffered > 0) pending.push(this.shift())

    for (let i = 0; i < pending.length - 1; i++) {
      const data = pending[i]
      this.buffered += this.byteLength(data)
      this.queue.push(data)
    }

    this.push(pending[pending.length - 1])
  }

  read () {
    const stream = this.stream

    if ((stream._duplexState & READ_STATUS) === READ_QUEUED) {
      const data = this.shift()
      if (this.pipeTo !== null && this.pipeTo.write(data) === false) stream._duplexState &= READ_PIPE_NOT_DRAINED
      if ((stream._duplexState & READ_EMIT_DATA) !== 0) stream.emit('data', data)
      return data
    }

    return null
  }

  drain () {
    const stream = this.stream

    while ((stream._duplexState & READ_STATUS) === READ_QUEUED && (stream._duplexState & READ_FLOWING) !== 0) {
      const data = this.shift()
      if (this.pipeTo !== null && this.pipeTo.write(data) === false) stream._duplexState &= READ_PIPE_NOT_DRAINED
      if ((stream._duplexState & READ_EMIT_DATA) !== 0) stream.emit('data', data)
    }
  }

  update () {
    const stream = this.stream

    stream._duplexState |= READ_UPDATING

    do {
      this.drain()

      while (this.buffered < this.highWaterMark && (stream._duplexState & SHOULD_NOT_READ) === 0) {
        stream._duplexState |= READ_ACTIVE_AND_NEEDS_PUSH
        stream._read(this.afterRead)
        this.drain()
      }

      if ((stream._duplexState & READ_READABLE_STATUS) === READ_EMIT_READABLE_AND_QUEUED) {
        stream._duplexState |= READ_EMITTED_READABLE
        stream.emit('readable')
      }

      if ((stream._duplexState & READ_PRIMARY_AND_ACTIVE) === 0) this.updateNonPrimary()
    } while (this.continueUpdate() === true)

    stream._duplexState &= READ_NOT_UPDATING
  }

  updateNonPrimary () {
    const stream = this.stream

    if ((stream._duplexState & READ_ENDING_STATUS) === READ_ENDING) {
      stream._duplexState = (stream._duplexState | READ_DONE) & READ_NOT_ENDING
      stream.emit('end')
      if ((stream._duplexState & AUTO_DESTROY) === DONE) stream._duplexState |= DESTROYING
      if (this.pipeTo !== null) this.pipeTo.end()
    }

    if ((stream._duplexState & DESTROY_STATUS) === DESTROYING) {
      if ((stream._duplexState & ACTIVE_OR_TICKING) === 0) {
        stream._duplexState |= ACTIVE
        stream._destroy(afterDestroy.bind(this))
      }
      return
    }

    if ((stream._duplexState & IS_OPENING) === OPENING) {
      stream._duplexState = (stream._duplexState | ACTIVE) & NOT_OPENING
      stream._open(afterOpen.bind(this))
    }
  }

  continueUpdate () {
    if ((this.stream._duplexState & READ_NEXT_TICK) === 0) return false
    this.stream._duplexState &= READ_NOT_NEXT_TICK
    return true
  }

  updateCallback () {
    if ((this.stream._duplexState & READ_UPDATE_SYNC_STATUS) === READ_PRIMARY) this.update()
    else this.updateNextTick()
  }

  updateNextTick () {
    if ((this.stream._duplexState & READ_NEXT_TICK) !== 0) return
    this.stream._duplexState |= READ_NEXT_TICK
    if ((this.stream._duplexState & READ_UPDATING) === 0) queueTick(this.afterUpdateNextTick)
  }
}

class TransformState {
  constructor (stream) {
    this.data = null
    this.afterTransform = afterTransform.bind(stream)
    this.afterFinal = null
  }
}

class Pipeline {
  constructor (src, dst, cb) {
    this.from = src
    this.to = dst
    this.afterPipe = cb
    this.error = null
    this.pipeToFinished = false
  }

  finished () {
    this.pipeToFinished = true
  }

  done (stream, err) {
    if (err) this.error = err

    if (stream === this.to) {
      this.to = null

      if (this.from !== null) {
        if ((this.from._duplexState & READ_DONE) === 0 || !this.pipeToFinished) {
          this.from.destroy(this.error || new Error('Writable stream closed prematurely'))
        }
        return
      }
    }

    if (stream === this.from) {
      this.from = null

      if (this.to !== null) {
        if ((stream._duplexState & READ_DONE) === 0) {
          this.to.destroy(this.error || new Error('Readable stream closed before ending'))
        }
        return
      }
    }

    if (this.afterPipe !== null) this.afterPipe(this.error)
    this.to = this.from = this.afterPipe = null
  }
}

function afterDrain () {
  this.stream._duplexState |= READ_PIPE_DRAINED
  this.updateCallback()
}

function afterFinal (err) {
  const stream = this.stream
  if (err) stream.destroy(err)
  if ((stream._duplexState & DESTROY_STATUS) === 0) {
    stream._duplexState |= WRITE_DONE
    stream.emit('finish')
  }
  if ((stream._duplexState & AUTO_DESTROY) === DONE) {
    stream._duplexState |= DESTROYING
  }

  stream._duplexState &= WRITE_NOT_ACTIVE

  // no need to wait the extra tick here, so we short circuit that
  if ((stream._duplexState & WRITE_UPDATING) === 0) this.update()
  else this.updateNextTick()
}

function afterDestroy (err) {
  const stream = this.stream

  if (!err && this.error !== STREAM_DESTROYED) err = this.error
  if (err) stream.emit('error', err)
  stream._duplexState |= DESTROYED
  stream.emit('close')

  const rs = stream._readableState
  const ws = stream._writableState

  if (rs !== null && rs.pipeline !== null) rs.pipeline.done(stream, err)

  if (ws !== null) {
    while (ws.drains !== null && ws.drains.length > 0) ws.drains.shift().resolve(false)
    if (ws.pipeline !== null) ws.pipeline.done(stream, err)
  }
}

function afterWrite (err) {
  const stream = this.stream

  if (err) stream.destroy(err)
  stream._duplexState &= WRITE_NOT_ACTIVE

  if (this.drains !== null) tickDrains(this.drains)

  if ((stream._duplexState & WRITE_DRAIN_STATUS) === WRITE_UNDRAINED) {
    stream._duplexState &= WRITE_DRAINED
    if ((stream._duplexState & WRITE_EMIT_DRAIN) === WRITE_EMIT_DRAIN) {
      stream.emit('drain')
    }
  }

  this.updateCallback()
}

function afterRead (err) {
  if (err) this.stream.destroy(err)
  this.stream._duplexState &= READ_NOT_ACTIVE
  this.updateCallback()
}

function updateReadNT () {
  if ((this.stream._duplexState & READ_UPDATING) === 0) {
    this.stream._duplexState &= READ_NOT_NEXT_TICK
    this.update()
  }
}

function updateWriteNT () {
  if ((this.stream._duplexState & WRITE_UPDATING) === 0) {
    this.stream._duplexState &= WRITE_NOT_NEXT_TICK
    this.update()
  }
}

function tickDrains (drains) {
  for (let i = 0; i < drains.length; i++) {
    // drains.writes are monotonic, so if one is 0 its always the first one
    if (--drains[i].writes === 0) {
      drains.shift().resolve(true)
      i--
    }
  }
}

function afterOpen (err) {
  const stream = this.stream

  if (err) stream.destroy(err)

  if ((stream._duplexState & DESTROYING) === 0) {
    if ((stream._duplexState & READ_PRIMARY_STATUS) === 0) stream._duplexState |= READ_PRIMARY
    if ((stream._duplexState & WRITE_PRIMARY_STATUS) === 0) stream._duplexState |= WRITE_PRIMARY
    stream.emit('open')
  }

  stream._duplexState &= NOT_ACTIVE

  if (stream._writableState !== null) {
    stream._writableState.updateCallback()
  }

  if (stream._readableState !== null) {
    stream._readableState.updateCallback()
  }
}

function afterTransform (err, data) {
  if (data !== undefined && data !== null) this.push(data)
  this._writableState.afterWrite(err)
}

class Stream extends EventEmitter {
  constructor (opts) {
    super()

    this._duplexState = 0
    this._readableState = null
    this._writableState = null

    if (opts) {
      if (opts.open) this._open = opts.open
      if (opts.destroy) this._destroy = opts.destroy
      if (opts.predestroy) this._predestroy = opts.predestroy
      if (opts.signal) {
        opts.signal.addEventListener('abort', abort.bind(this))
      }
    }
  }

  _open (cb) {
    cb(null)
  }

  _destroy (cb) {
    cb(null)
  }

  _predestroy () {
    // does nothing
  }

  get readable () {
    return this._readableState !== null ? true : undefined
  }

  get writable () {
    return this._writableState !== null ? true : undefined
  }

  get destroyed () {
    return (this._duplexState & DESTROYED) !== 0
  }

  get destroying () {
    return (this._duplexState & DESTROY_STATUS) !== 0
  }

  destroy (err) {
    if ((this._duplexState & DESTROY_STATUS) === 0) {
      if (!err) err = STREAM_DESTROYED
      this._duplexState = (this._duplexState | DESTROYING) & NON_PRIMARY

      if (this._readableState !== null) {
        this._readableState.highWaterMark = 0
        this._readableState.error = err
      }
      if (this._writableState !== null) {
        this._writableState.highWaterMark = 0
        this._writableState.error = err
      }

      this._duplexState |= PREDESTROYING
      this._predestroy()
      this._duplexState &= NOT_PREDESTROYING

      if (this._readableState !== null) this._readableState.updateNextTick()
      if (this._writableState !== null) this._writableState.updateNextTick()
    }
  }

  on (name, fn) {
    if (this._readableState !== null) {
      if (name === 'data') {
        this._duplexState |= (READ_EMIT_DATA | READ_RESUMED)
        this._readableState.updateNextTick()
      }
      if (name === 'readable') {
        this._duplexState |= READ_EMIT_READABLE
        this._readableState.updateNextTick()
      }
    }

    if (this._writableState !== null) {
      if (name === 'drain') {
        this._duplexState |= WRITE_EMIT_DRAIN
        this._writableState.updateNextTick()
      }
    }

    return super.on(name, fn)
  }
}

class Readable extends Stream {
  constructor (opts) {
    super(opts)

    this._duplexState |= OPENING | WRITE_DONE
    this._readableState = new ReadableState(this, opts)

    if (opts) {
      if (opts.read) this._read = opts.read
      if (opts.eagerOpen) this._readableState.updateNextTick()
    }
  }

  _read (cb) {
    cb(null)
  }

  pipe (dest, cb) {
    this._readableState.updateNextTick()
    this._readableState.pipe(dest, cb)
    return dest
  }

  read () {
    this._readableState.updateNextTick()
    return this._readableState.read()
  }

  push (data) {
    this._readableState.updateNextTick()
    return this._readableState.push(data)
  }

  unshift (data) {
    this._readableState.updateNextTick()
    return this._readableState.unshift(data)
  }

  resume () {
    this._duplexState |= READ_RESUMED
    this._readableState.updateNextTick()
    return this
  }

  pause () {
    this._duplexState &= READ_PAUSED
    return this
  }

  static _fromAsyncIterator (ite, opts) {
    let destroy

    const rs = new Readable({
      ...opts,
      read (cb) {
        ite.next().then(push).then(cb.bind(null, null)).catch(cb)
      },
      predestroy () {
        destroy = ite.return()
      },
      destroy (cb) {
        if (!destroy) return cb(null)
        destroy.then(cb.bind(null, null)).catch(cb)
      }
    })

    return rs

    function push (data) {
      if (data.done) rs.push(null)
      else rs.push(data.value)
    }
  }

  static from (data, opts) {
    if (isReadStreamx(data)) return data
    if (data[asyncIterator]) return this._fromAsyncIterator(data[asyncIterator](), opts)
    if (!Array.isArray(data)) data = data === undefined ? [] : [data]

    let i = 0
    return new Readable({
      ...opts,
      read (cb) {
        this.push(i === data.length ? null : data[i++])
        cb(null)
      }
    })
  }

  static isBackpressured (rs) {
    return (rs._duplexState & READ_BACKPRESSURE_STATUS) !== 0 || rs._readableState.buffered >= rs._readableState.highWaterMark
  }

  static isPaused (rs) {
    return (rs._duplexState & READ_RESUMED) === 0
  }

  [asyncIterator] () {
    const stream = this

    let error = null
    let promiseResolve = null
    let promiseReject = null

    this.on('error', (err) => { error = err })
    this.on('readable', onreadable)
    this.on('close', onclose)

    return {
      [asyncIterator] () {
        return this
      },
      next () {
        return new Promise(function (resolve, reject) {
          promiseResolve = resolve
          promiseReject = reject
          const data = stream.read()
          if (data !== null) ondata(data)
          else if ((stream._duplexState & DESTROYED) !== 0) ondata(null)
        })
      },
      return () {
        return destroy(null)
      },
      throw (err) {
        return destroy(err)
      }
    }

    function onreadable () {
      if (promiseResolve !== null) ondata(stream.read())
    }

    function onclose () {
      if (promiseResolve !== null) ondata(null)
    }

    function ondata (data) {
      if (promiseReject === null) return
      if (error) promiseReject(error)
      else if (data === null && (stream._duplexState & READ_DONE) === 0) promiseReject(STREAM_DESTROYED)
      else promiseResolve({ value: data, done: data === null })
      promiseReject = promiseResolve = null
    }

    function destroy (err) {
      stream.destroy(err)
      return new Promise((resolve, reject) => {
        if (stream._duplexState & DESTROYED) return resolve({ value: undefined, done: true })
        stream.once('close', function () {
          if (err) reject(err)
          else resolve({ value: undefined, done: true })
        })
      })
    }
  }
}

class Writable extends Stream {
  constructor (opts) {
    super(opts)

    this._duplexState |= OPENING | READ_DONE
    this._writableState = new WritableState(this, opts)

    if (opts) {
      if (opts.writev) this._writev = opts.writev
      if (opts.write) this._write = opts.write
      if (opts.final) this._final = opts.final
      if (opts.eagerOpen) this._writableState.updateNextTick()
    }
  }

  _writev (batch, cb) {
    cb(null)
  }

  _write (data, cb) {
    this._writableState.autoBatch(data, cb)
  }

  _final (cb) {
    cb(null)
  }

  static isBackpressured (ws) {
    return (ws._duplexState & WRITE_BACKPRESSURE_STATUS) !== 0
  }

  static drained (ws) {
    if (ws.destroyed) return Promise.resolve(false)
    const state = ws._writableState
    const pending = (isWritev(ws) ? Math.min(1, state.queue.length) : state.queue.length)
    const writes = pending + ((ws._duplexState & WRITE_WRITING) ? 1 : 0)
    if (writes === 0) return Promise.resolve(true)
    if (state.drains === null) state.drains = []
    return new Promise((resolve) => {
      state.drains.push({ writes, resolve })
    })
  }

  write (data) {
    this._writableState.updateNextTick()
    return this._writableState.push(data)
  }

  end (data) {
    this._writableState.updateNextTick()
    this._writableState.end(data)
    return this
  }
}

class Duplex extends Readable { // and Writable
  constructor (opts) {
    super(opts)

    this._duplexState = OPENING
    this._writableState = new WritableState(this, opts)

    if (opts) {
      if (opts.writev) this._writev = opts.writev
      if (opts.write) this._write = opts.write
      if (opts.final) this._final = opts.final
    }
  }

  _writev (batch, cb) {
    cb(null)
  }

  _write (data, cb) {
    this._writableState.autoBatch(data, cb)
  }

  _final (cb) {
    cb(null)
  }

  write (data) {
    this._writableState.updateNextTick()
    return this._writableState.push(data)
  }

  end (data) {
    this._writableState.updateNextTick()
    this._writableState.end(data)
    return this
  }
}

class Transform extends Duplex {
  constructor (opts) {
    super(opts)
    this._transformState = new TransformState(this)

    if (opts) {
      if (opts.transform) this._transform = opts.transform
      if (opts.flush) this._flush = opts.flush
    }
  }

  _write (data, cb) {
    if (this._readableState.buffered >= this._readableState.highWaterMark) {
      this._transformState.data = data
    } else {
      this._transform(data, this._transformState.afterTransform)
    }
  }

  _read (cb) {
    if (this._transformState.data !== null) {
      const data = this._transformState.data
      this._transformState.data = null
      cb(null)
      this._transform(data, this._transformState.afterTransform)
    } else {
      cb(null)
    }
  }

  destroy (err) {
    super.destroy(err)
    if (this._transformState.data !== null) {
      this._transformState.data = null
      this._transformState.afterTransform()
    }
  }

  _transform (data, cb) {
    cb(null, data)
  }

  _flush (cb) {
    cb(null)
  }

  _final (cb) {
    this._transformState.afterFinal = cb
    this._flush(transformAfterFlush.bind(this))
  }
}

class PassThrough extends Transform {}

function transformAfterFlush (err, data) {
  const cb = this._transformState.afterFinal
  if (err) return cb(err)
  if (data !== null && data !== undefined) this.push(data)
  this.push(null)
  cb(null)
}

function pipelinePromise (...streams) {
  return new Promise((resolve, reject) => {
    return pipeline(...streams, (err) => {
      if (err) return reject(err)
      resolve()
    })
  })
}

function pipeline (stream, ...streams) {
  const all = Array.isArray(stream) ? [...stream, ...streams] : [stream, ...streams]
  const done = (all.length && typeof all[all.length - 1] === 'function') ? all.pop() : null

  if (all.length < 2) throw new Error('Pipeline requires at least 2 streams')

  let src = all[0]
  let dest = null
  let error = null

  for (let i = 1; i < all.length; i++) {
    dest = all[i]

    if (isStreamx(src)) {
      src.pipe(dest, onerror)
    } else {
      errorHandle(src, true, i > 1, onerror)
      src.pipe(dest)
    }

    src = dest
  }

  if (done) {
    let fin = false

    const autoDestroy = isStreamx(dest) || !!(dest._writableState && dest._writableState.autoDestroy)

    dest.on('error', (err) => {
      if (error === null) error = err
    })

    dest.on('finish', () => {
      fin = true
      if (!autoDestroy) done(error)
    })

    if (autoDestroy) {
      dest.on('close', () => done(error || (fin ? null : PREMATURE_CLOSE)))
    }
  }

  return dest

  function errorHandle (s, rd, wr, onerror) {
    s.on('error', onerror)
    s.on('close', onclose)

    function onclose () {
      if (rd && s._readableState && !s._readableState.ended) return onerror(PREMATURE_CLOSE)
      if (wr && s._writableState && !s._writableState.ended) return onerror(PREMATURE_CLOSE)
    }
  }

  function onerror (err) {
    if (!err || error) return
    error = err

    for (const s of all) {
      s.destroy(err)
    }
  }
}

function isStream (stream) {
  return !!stream._readableState || !!stream._writableState
}

function isStreamx (stream) {
  return typeof stream._duplexState === 'number' && isStream(stream)
}

function getStreamError (stream) {
  const err = (stream._readableState && stream._readableState.error) || (stream._writableState && stream._writableState.error)
  return err === STREAM_DESTROYED ? null : err // only explicit errors
}

function isReadStreamx (stream) {
  return isStreamx(stream) && stream.readable
}

function isTypedArray (data) {
  return typeof data === 'object' && data !== null && typeof data.byteLength === 'number'
}

function defaultByteLength (data) {
  return isTypedArray(data) ? data.byteLength : 1024
}

function noop () {}

function abort () {
  this.destroy(new Error('Stream aborted.'))
}

function isWritev (s) {
  return s._writev !== Writable.prototype._writev && s._writev !== Duplex.prototype._writev
}

module.exports = {
  pipeline,
  pipelinePromise,
  isStream,
  isStreamx,
  getStreamError,
  Stream,
  Writable,
  Readable,
  Duplex,
  Transform,
  // Export PassThrough for compatibility with Node.js core's stream module
  PassThrough
}

},{"events":22,"fast-fifo":24,"queue-tick":59}],129:[function(require,module,exports){
module.exports = class TimerBrowser {
  constructor (ms, fn, ctx = null, interval = false) {
    this.ms = ms
    this.ontimeout = fn
    this.context = ctx || null
    this.interval = interval
    this.done = false

    this._timer = interval
      ? setInterval(callInterval, ms, this)
      : setTimeout(callTimeout, ms, this)
  }

  unref () {}

  ref () {}

  refresh () {
    if (this.done) return

    if (this.interval) {
      clearInterval(this._timer)
      this._timer = setInterval(callInterval, this.ms, this)
    } else {
      clearTimeout(this._timer)
      this._timer = setTimeout(callTimeout, this.ms, this)
    }
  }

  destroy () {
    this.done = true
    this.ontimeout = null

    if (this.interval) clearInterval(this._timer)
    else clearTimeout(this._timer)
  }

  static once (ms, fn, ctx) {
    return new this(ms, fn, ctx, false)
  }

  static on (ms, fn, ctx) {
    return new this(ms, fn, ctx, true)
  }
}

function callTimeout (self) {
  self.done = true
  self.ontimeout.call(self.context)
}

function callInterval (self) {
  self.ontimeout.call(self.context)
}

},{}],130:[function(require,module,exports){
module.exports = class MaxCache {
  constructor ({ maxSize, maxAge, createMap, ongc }) {
    this.maxSize = maxSize
    this.maxAge = maxAge
    this.ongc = ongc || null

    this._createMap = createMap || defaultCreateMap
    this._latest = this._createMap()
    this._oldest = this._createMap()
    this._retained = this._createMap()
    this._gced = false
    this._interval = null

    if (this.maxAge > 0 && this.maxAge < Infinity) {
      const tick = Math.ceil(2 / 3 * this.maxAge)
      this._interval = setInterval(this._gcAuto.bind(this), tick)
      if (this._interval.unref) this._interval.unref()
    }
  }

  * [Symbol.iterator] () {
    for (const it of [this._latest, this._oldest, this._retained]) {
      yield * it
    }
  }

  * keys () {
    for (const it of [this._latest, this._oldest, this._retained]) {
      yield * it.keys()
    }
  }

  * values () {
    for (const it of [this._latest, this._oldest, this._retained]) {
      yield * it.values()
    }
  }

  destroy () {
    this.clear()
    clearInterval(this._interval)
    this._interval = null
  }

  clear () {
    this._gced = true
    this._latest.clear()
    this._oldest.clear()
    this._retained.clear()
  }

  set (k, v) {
    if (this._retained.has(k)) return this
    this._latest.set(k, v)
    this._oldest.delete(k) || this._retained.delete(k)
    if (this._latest.size >= this.maxSize) this._gc()
    return this
  }

  retain (k, v) {
    this._retained.set(k, v)
    this._latest.delete(k) || this._oldest.delete(k)
    return this
  }

  delete (k) {
    return this._latest.delete(k) || this._oldest.delete(k) || this._retained.delete(k)
  }

  has (k) {
    return this._latest.has(k) || this._oldest.has(k) || this._retained.has(k)
  }

  get (k) {
    if (this._latest.has(k)) {
      return this._latest.get(k)
    }

    if (this._oldest.has(k)) {
      const v = this._oldest.get(k)
      this._latest.set(k, v)
      this._oldest.delete(k)
      return v
    }

    if (this._retained.has(k)) {
      return this._retained.get(k)
    }

    return null
  }

  _gcAuto () {
    if (!this._gced) this._gc()
    this._gced = false
  }

  _gc () {
    this._gced = true
    if (this.ongc !== null && this._oldest.size > 0) this.ongc(this._oldest)
    this._oldest = this._latest
    this._latest = this._createMap()
  }
}

function defaultCreateMap () {
  return new Map()
}

},{}],131:[function(require,module,exports){
var xsalsa20 = typeof WebAssembly !== "undefined" && require('./xsalsa20')()

var SIGMA = new Uint8Array([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107])
var head = 144
var top = head
var free = []

module.exports = XSalsa20

XSalsa20.NONCEBYTES = 24
XSalsa20.KEYBYTES = 32

XSalsa20.core_hsalsa20 = core_hsalsa20
XSalsa20.SIGMA = SIGMA

function XSalsa20 (nonce, key) {
  if (!(this instanceof XSalsa20)) return new XSalsa20(nonce, key)
  if (!nonce || nonce.length < 24) throw new Error('nonce must be at least 24 bytes')
  if (!key || key.length < 32) throw new Error('key must be at least 32 bytes')
  this._xor = xsalsa20 ? new WASM(nonce, key) : new Fallback(nonce, key)
}

XSalsa20.prototype.update = function (input, output) {
  if (!input) throw new Error('input must be Uint8Array or Buffer')
  if (!output) output = new Uint8Array(input.length)
  if (input.length) this._xor.update(input, output)
  return output
}

XSalsa20.prototype.final =
XSalsa20.prototype.finalize = function () {
  this._xor.finalize()
  this._xor = null
}

function WASM (nonce, key) {
  if (!free.length) {
    free.push(head)
    head += 64
  }

  this._pointer = free.pop()
  this._nonce = this._pointer + 8
  this._key = this._nonce + 24
  this._overflow = 0
  this._memory = new Uint8Array(xsalsa20.memory.buffer)

  this._memory.fill(0, this._pointer, this._pointer + 8)
  this._memory.set(nonce, this._nonce)
  this._memory.set(key, this._key)
}

WASM.prototype.realloc = function (size) {
  xsalsa20.memory.grow(Math.ceil(Math.abs(size - this._memory.length) / 65536))
  this._memory = new Uint8Array(xsalsa20.memory.buffer)
}

WASM.prototype.update = function (input, output) {
  var len = this._overflow + input.length
  var start = head + this._overflow

  top = head + len
  if (top >= this._memory.length) this.realloc(top)

  this._memory.set(input, start)
  xsalsa20.xsalsa20_xor(this._pointer, head, head, len, this._nonce, this._key)
  output.set(this._memory.subarray(start, head + len))

  this._overflow = len & 63
}

WASM.prototype.finalize = function () {
  this._memory.fill(0, this._pointer, this._key + 32)
  if (top > head) {
    this._memory.fill(0, head, top)
    top = 0
  }
  free.push(this._pointer)
}

function Fallback (nonce, key) {
  this._s = new Uint8Array(32)
  this._z = new Uint8Array(16)
  this._overflow = 0
  core_hsalsa20(this._s, nonce, key, SIGMA)
  for (var i = 0; i < 8; i++) this._z[i] = nonce[i + 16]
}

Fallback.prototype.update = function (input, output) {
  var x = new Uint8Array(64)
  var u = 0
  var i = this._overflow
  var b = input.length + this._overflow
  var z = this._z
  var mpos = -this._overflow
  var cpos = -this._overflow

  while (b >= 64) {
    core_salsa20(x, z, this._s, SIGMA)
    for (; i < 64; i++) output[cpos + i] = input[mpos + i] ^ x[i]
    u = 1
    for (i = 8; i < 16; i++) {
      u += (z[i] & 0xff) | 0
      z[i] = u & 0xff
      u >>>= 8
    }
    b -= 64
    cpos += 64
    mpos += 64
    i = 0
  }
  if (b > 0) {
    core_salsa20(x, z, this._s, SIGMA)
    for (; i < b; i++) output[cpos + i] = input[mpos + i] ^ x[i]
  }

  this._overflow = b & 63
}

Fallback.prototype.finalize = function () {
  this._s.fill(0)
  this._z.fill(0)
}

// below methods are ported from tweet nacl

function core_salsa20(o, p, k, c) {
  var j0  = c[ 0] & 0xff | (c[ 1] & 0xff) << 8 | (c[ 2] & 0xff) << 16 | (c[ 3] & 0xff) << 24,
      j1  = k[ 0] & 0xff | (k[ 1] & 0xff) << 8 | (k[ 2] & 0xff) << 16 | (k[ 3] & 0xff) << 24,
      j2  = k[ 4] & 0xff | (k[ 5] & 0xff) << 8 | (k[ 6] & 0xff) << 16 | (k[ 7] & 0xff) << 24,
      j3  = k[ 8] & 0xff | (k[ 9] & 0xff) << 8 | (k[10] & 0xff) << 16 | (k[11] & 0xff) << 24,
      j4  = k[12] & 0xff | (k[13] & 0xff) << 8 | (k[14] & 0xff) << 16 | (k[15] & 0xff) << 24,
      j5  = c[ 4] & 0xff | (c[ 5] & 0xff) << 8 | (c[ 6] & 0xff) << 16 | (c[ 7] & 0xff) << 24,
      j6  = p[ 0] & 0xff | (p[ 1] & 0xff) << 8 | (p[ 2] & 0xff) << 16 | (p[ 3] & 0xff) << 24,
      j7  = p[ 4] & 0xff | (p[ 5] & 0xff) << 8 | (p[ 6] & 0xff) << 16 | (p[ 7] & 0xff) << 24,
      j8  = p[ 8] & 0xff | (p[ 9] & 0xff) << 8 | (p[10] & 0xff) << 16 | (p[11] & 0xff) << 24,
      j9  = p[12] & 0xff | (p[13] & 0xff) << 8 | (p[14] & 0xff) << 16 | (p[15] & 0xff) << 24,
      j10 = c[ 8] & 0xff | (c[ 9] & 0xff) << 8 | (c[10] & 0xff) << 16 | (c[11] & 0xff) << 24,
      j11 = k[16] & 0xff | (k[17] & 0xff) << 8 | (k[18] & 0xff) << 16 | (k[19] & 0xff) << 24,
      j12 = k[20] & 0xff | (k[21] & 0xff) << 8 | (k[22] & 0xff) << 16 | (k[23] & 0xff) << 24,
      j13 = k[24] & 0xff | (k[25] & 0xff) << 8 | (k[26] & 0xff) << 16 | (k[27] & 0xff) << 24,
      j14 = k[28] & 0xff | (k[29] & 0xff) << 8 | (k[30] & 0xff) << 16 | (k[31] & 0xff) << 24,
      j15 = c[12] & 0xff | (c[13] & 0xff) << 8 | (c[14] & 0xff) << 16 | (c[15] & 0xff) << 24

  var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7,
      x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14,
      x15 = j15, u

  for (var i = 0; i < 20; i += 2) {
    u = x0 + x12 | 0
    x4 ^= u << 7 | u >>> 25
    u = x4 + x0 | 0
    x8 ^= u << 9 | u >>> 23
    u = x8 + x4 | 0
    x12 ^= u << 13 | u >>> 19
    u = x12 + x8 | 0
    x0 ^= u << 18 | u >>> 14

    u = x5 + x1 | 0
    x9 ^= u << 7 | u >>> 25
    u = x9 + x5 | 0
    x13 ^= u << 9 | u >>> 23
    u = x13 + x9 | 0
    x1 ^= u << 13 | u >>> 19
    u = x1 + x13 | 0
    x5 ^= u << 18 | u >>> 14

    u = x10 + x6 | 0
    x14 ^= u << 7 | u >>> 25
    u = x14 + x10 | 0
    x2 ^= u << 9 | u >>> 23
    u = x2 + x14 | 0
    x6 ^= u << 13 | u >>> 19
    u = x6 + x2 | 0
    x10 ^= u << 18 | u >>> 14

    u = x15 + x11 | 0
    x3 ^= u << 7 | u >>> 25
    u = x3 + x15 | 0
    x7 ^= u << 9 | u >>> 23
    u = x7 + x3 | 0
    x11 ^= u << 13 | u >>> 19
    u = x11 + x7 | 0
    x15 ^= u << 18 | u >>> 14

    u = x0 + x3 | 0
    x1 ^= u << 7 | u >>> 25
    u = x1 + x0 | 0
    x2 ^= u << 9 | u >>> 23
    u = x2 + x1 | 0
    x3 ^= u << 13 | u >>> 19
    u = x3 + x2 | 0
    x0 ^= u << 18 | u >>> 14

    u = x5 + x4 | 0
    x6 ^= u << 7 | u >>> 25
    u = x6 + x5 | 0
    x7 ^= u << 9 | u >>> 23
    u = x7 + x6 | 0
    x4 ^= u << 13 | u >>> 19
    u = x4 + x7 | 0
    x5 ^= u << 18 | u >>> 14

    u = x10 + x9 | 0
    x11 ^= u << 7 | u >>> 25
    u = x11 + x10 | 0
    x8 ^= u << 9 | u >>> 23
    u = x8 + x11 | 0
    x9 ^= u << 13 | u >>> 19
    u = x9 + x8 | 0
    x10 ^= u << 18 | u >>> 14

    u = x15 + x14 | 0
    x12 ^= u << 7 | u >>> 25
    u = x12 + x15 | 0
    x13 ^= u << 9 | u >>> 23
    u = x13 + x12 | 0
    x14 ^= u << 13 | u >>> 19
    u = x14 + x13 | 0
    x15 ^= u << 18 | u >>> 14
  }
   x0 =  x0 +  j0 | 0
   x1 =  x1 +  j1 | 0
   x2 =  x2 +  j2 | 0
   x3 =  x3 +  j3 | 0
   x4 =  x4 +  j4 | 0
   x5 =  x5 +  j5 | 0
   x6 =  x6 +  j6 | 0
   x7 =  x7 +  j7 | 0
   x8 =  x8 +  j8 | 0
   x9 =  x9 +  j9 | 0
  x10 = x10 + j10 | 0
  x11 = x11 + j11 | 0
  x12 = x12 + j12 | 0
  x13 = x13 + j13 | 0
  x14 = x14 + j14 | 0
  x15 = x15 + j15 | 0

  o[ 0] = x0 >>>  0 & 0xff
  o[ 1] = x0 >>>  8 & 0xff
  o[ 2] = x0 >>> 16 & 0xff
  o[ 3] = x0 >>> 24 & 0xff

  o[ 4] = x1 >>>  0 & 0xff
  o[ 5] = x1 >>>  8 & 0xff
  o[ 6] = x1 >>> 16 & 0xff
  o[ 7] = x1 >>> 24 & 0xff

  o[ 8] = x2 >>>  0 & 0xff
  o[ 9] = x2 >>>  8 & 0xff
  o[10] = x2 >>> 16 & 0xff
  o[11] = x2 >>> 24 & 0xff

  o[12] = x3 >>>  0 & 0xff
  o[13] = x3 >>>  8 & 0xff
  o[14] = x3 >>> 16 & 0xff
  o[15] = x3 >>> 24 & 0xff

  o[16] = x4 >>>  0 & 0xff
  o[17] = x4 >>>  8 & 0xff
  o[18] = x4 >>> 16 & 0xff
  o[19] = x4 >>> 24 & 0xff

  o[20] = x5 >>>  0 & 0xff
  o[21] = x5 >>>  8 & 0xff
  o[22] = x5 >>> 16 & 0xff
  o[23] = x5 >>> 24 & 0xff

  o[24] = x6 >>>  0 & 0xff
  o[25] = x6 >>>  8 & 0xff
  o[26] = x6 >>> 16 & 0xff
  o[27] = x6 >>> 24 & 0xff

  o[28] = x7 >>>  0 & 0xff
  o[29] = x7 >>>  8 & 0xff
  o[30] = x7 >>> 16 & 0xff
  o[31] = x7 >>> 24 & 0xff

  o[32] = x8 >>>  0 & 0xff
  o[33] = x8 >>>  8 & 0xff
  o[34] = x8 >>> 16 & 0xff
  o[35] = x8 >>> 24 & 0xff

  o[36] = x9 >>>  0 & 0xff
  o[37] = x9 >>>  8 & 0xff
  o[38] = x9 >>> 16 & 0xff
  o[39] = x9 >>> 24 & 0xff

  o[40] = x10 >>>  0 & 0xff
  o[41] = x10 >>>  8 & 0xff
  o[42] = x10 >>> 16 & 0xff
  o[43] = x10 >>> 24 & 0xff

  o[44] = x11 >>>  0 & 0xff
  o[45] = x11 >>>  8 & 0xff
  o[46] = x11 >>> 16 & 0xff
  o[47] = x11 >>> 24 & 0xff

  o[48] = x12 >>>  0 & 0xff
  o[49] = x12 >>>  8 & 0xff
  o[50] = x12 >>> 16 & 0xff
  o[51] = x12 >>> 24 & 0xff

  o[52] = x13 >>>  0 & 0xff
  o[53] = x13 >>>  8 & 0xff
  o[54] = x13 >>> 16 & 0xff
  o[55] = x13 >>> 24 & 0xff

  o[56] = x14 >>>  0 & 0xff
  o[57] = x14 >>>  8 & 0xff
  o[58] = x14 >>> 16 & 0xff
  o[59] = x14 >>> 24 & 0xff

  o[60] = x15 >>>  0 & 0xff
  o[61] = x15 >>>  8 & 0xff
  o[62] = x15 >>> 16 & 0xff
  o[63] = x15 >>> 24 & 0xff
}

function core_hsalsa20(o,p,k,c) {
  var j0  = c[ 0] & 0xff | (c[ 1] & 0xff) << 8 | (c[ 2] & 0xff) << 16 | (c[ 3] & 0xff) << 24,
      j1  = k[ 0] & 0xff | (k[ 1] & 0xff) << 8 | (k[ 2] & 0xff) << 16 | (k[ 3] & 0xff) << 24,
      j2  = k[ 4] & 0xff | (k[ 5] & 0xff) << 8 | (k[ 6] & 0xff) << 16 | (k[ 7] & 0xff) << 24,
      j3  = k[ 8] & 0xff | (k[ 9] & 0xff) << 8 | (k[10] & 0xff) << 16 | (k[11] & 0xff) << 24,
      j4  = k[12] & 0xff | (k[13] & 0xff) << 8 | (k[14] & 0xff) << 16 | (k[15] & 0xff) << 24,
      j5  = c[ 4] & 0xff | (c[ 5] & 0xff) << 8 | (c[ 6] & 0xff) << 16 | (c[ 7] & 0xff) << 24,
      j6  = p[ 0] & 0xff | (p[ 1] & 0xff) << 8 | (p[ 2] & 0xff) << 16 | (p[ 3] & 0xff) << 24,
      j7  = p[ 4] & 0xff | (p[ 5] & 0xff) << 8 | (p[ 6] & 0xff) << 16 | (p[ 7] & 0xff) << 24,
      j8  = p[ 8] & 0xff | (p[ 9] & 0xff) << 8 | (p[10] & 0xff) << 16 | (p[11] & 0xff) << 24,
      j9  = p[12] & 0xff | (p[13] & 0xff) << 8 | (p[14] & 0xff) << 16 | (p[15] & 0xff) << 24,
      j10 = c[ 8] & 0xff | (c[ 9] & 0xff) << 8 | (c[10] & 0xff) << 16 | (c[11] & 0xff) << 24,
      j11 = k[16] & 0xff | (k[17] & 0xff) << 8 | (k[18] & 0xff) << 16 | (k[19] & 0xff) << 24,
      j12 = k[20] & 0xff | (k[21] & 0xff) << 8 | (k[22] & 0xff) << 16 | (k[23] & 0xff) << 24,
      j13 = k[24] & 0xff | (k[25] & 0xff) << 8 | (k[26] & 0xff) << 16 | (k[27] & 0xff) << 24,
      j14 = k[28] & 0xff | (k[29] & 0xff) << 8 | (k[30] & 0xff) << 16 | (k[31] & 0xff) << 24,
      j15 = c[12] & 0xff | (c[13] & 0xff) << 8 | (c[14] & 0xff) << 16 | (c[15] & 0xff) << 24

  var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7,
      x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14,
      x15 = j15, u

  for (var i = 0; i < 20; i += 2) {
    u = x0 + x12 | 0
    x4 ^= u << 7 | u >>> 25
    u = x4 + x0 | 0
    x8 ^= u << 9 | u >>> 23
    u = x8 + x4 | 0
    x12 ^= u << 13 | u >>> 19
    u = x12 + x8 | 0
    x0 ^= u << 18 | u >>> 14

    u = x5 + x1 | 0
    x9 ^= u << 7 | u >>> 25
    u = x9 + x5 | 0
    x13 ^= u << 9 | u >>> 23
    u = x13 + x9 | 0
    x1 ^= u << 13 | u >>> 19
    u = x1 + x13 | 0
    x5 ^= u << 18 | u >>> 14

    u = x10 + x6 | 0
    x14 ^= u << 7 | u >>> 25
    u = x14 + x10 | 0
    x2 ^= u << 9 | u >>> 23
    u = x2 + x14 | 0
    x6 ^= u << 13 | u >>> 19
    u = x6 + x2 | 0
    x10 ^= u << 18 | u >>> 14

    u = x15 + x11 | 0
    x3 ^= u << 7 | u >>> 25
    u = x3 + x15 | 0
    x7 ^= u << 9 | u >>> 23
    u = x7 + x3 | 0
    x11 ^= u << 13 | u >>> 19
    u = x11 + x7 | 0
    x15 ^= u << 18 | u >>> 14

    u = x0 + x3 | 0
    x1 ^= u << 7 | u >>> 25
    u = x1 + x0 | 0
    x2 ^= u << 9 | u >>> 23
    u = x2 + x1 | 0
    x3 ^= u << 13 | u >>> 19
    u = x3 + x2 | 0
    x0 ^= u << 18 | u >>> 14

    u = x5 + x4 | 0
    x6 ^= u << 7 | u >>> 25
    u = x6 + x5 | 0
    x7 ^= u << 9 | u >>> 23
    u = x7 + x6 | 0
    x4 ^= u << 13 | u >>> 19
    u = x4 + x7 | 0
    x5 ^= u << 18 | u >>> 14

    u = x10 + x9 | 0
    x11 ^= u << 7 | u >>> 25
    u = x11 + x10 | 0
    x8 ^= u << 9 | u >>> 23
    u = x8 + x11 | 0
    x9 ^= u << 13 | u >>> 19
    u = x9 + x8 | 0
    x10 ^= u << 18 | u >>> 14

    u = x15 + x14 | 0
    x12 ^= u << 7 | u >>> 25
    u = x12 + x15 | 0
    x13 ^= u << 9 | u >>> 23
    u = x13 + x12 | 0
    x14 ^= u << 13 | u >>> 19
    u = x14 + x13 | 0
    x15 ^= u << 18 | u >>> 14
  }

  o[ 0] = x0 >>>  0 & 0xff
  o[ 1] = x0 >>>  8 & 0xff
  o[ 2] = x0 >>> 16 & 0xff
  o[ 3] = x0 >>> 24 & 0xff

  o[ 4] = x5 >>>  0 & 0xff
  o[ 5] = x5 >>>  8 & 0xff
  o[ 6] = x5 >>> 16 & 0xff
  o[ 7] = x5 >>> 24 & 0xff

  o[ 8] = x10 >>>  0 & 0xff
  o[ 9] = x10 >>>  8 & 0xff
  o[10] = x10 >>> 16 & 0xff
  o[11] = x10 >>> 24 & 0xff

  o[12] = x15 >>>  0 & 0xff
  o[13] = x15 >>>  8 & 0xff
  o[14] = x15 >>> 16 & 0xff
  o[15] = x15 >>> 24 & 0xff

  o[16] = x6 >>>  0 & 0xff
  o[17] = x6 >>>  8 & 0xff
  o[18] = x6 >>> 16 & 0xff
  o[19] = x6 >>> 24 & 0xff

  o[20] = x7 >>>  0 & 0xff
  o[21] = x7 >>>  8 & 0xff
  o[22] = x7 >>> 16 & 0xff
  o[23] = x7 >>> 24 & 0xff

  o[24] = x8 >>>  0 & 0xff
  o[25] = x8 >>>  8 & 0xff
  o[26] = x8 >>> 16 & 0xff
  o[27] = x8 >>> 24 & 0xff

  o[28] = x9 >>>  0 & 0xff
  o[29] = x9 >>>  8 & 0xff
  o[30] = x9 >>> 16 & 0xff
  o[31] = x9 >>> 24 & 0xff
}

},{"./xsalsa20":132}],132:[function(require,module,exports){
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[Object.keys(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __toBinary = /* @__PURE__ */ (() => {
  var table = new Uint8Array(128);
  for (var i = 0; i < 64; i++)
    table[i < 26 ? i + 65 : i < 52 ? i + 71 : i < 62 ? i - 4 : i * 4 - 205] = i;
  return (base64) => {
    var n = base64.length, bytes2 = new Uint8Array((n - (base64[n - 1] == "=") - (base64[n - 2] == "=")) * 3 / 4 | 0);
    for (var i2 = 0, j = 0; i2 < n; ) {
      var c0 = table[base64.charCodeAt(i2++)], c1 = table[base64.charCodeAt(i2++)];
      var c2 = table[base64.charCodeAt(i2++)], c3 = table[base64.charCodeAt(i2++)];
      bytes2[j++] = c0 << 2 | c1 >> 4;
      bytes2[j++] = c1 << 4 | c2 >> 2;
      bytes2[j++] = c2 << 6 | c3;
    }
    return bytes2;
  };
})();

// wasm-binary:./xsalsa20.wat
var require_xsalsa20 = __commonJS({
  "wasm-binary:./xsalsa20.wat"(exports2, module2) {
    module2.exports = __toBinary("AGFzbQEAAAABGgNgBn9/f39/fwBgBn9/f39+fwF+YAN/f38AAwcGAAEBAgICBQUBAQroBwcoAwZtZW1vcnkCAAx4c2Fsc2EyMF94b3IAAAxjb3JlX3NhbHNhMjAABArqEQYYACAAIAEgAiADIAQgACkDACAFEAE3AwALPQBB8AAgAyAFEAMgACABIAIgA0EQaiAEQfAAEAJB8ABCADcDAEH4AEIANwMAQYABQgA3AwBBiAFCADcDAAuHBQEBfyACQQBGBEBCAA8LQdAAIAUpAwA3AwBB2AAgBUEIaikDADcDAEHgACAFQRBqKQMANwMAQegAIAVBGGopAwA3AwBBACADKQMANwMAQQggBDcDAAJAA0AgAkHAAEkNAUEQQQBB0AAQBSAAIAEpAwBBECkDAIU3AwAgAEEIaiABQQhqKQMAQRgpAwCFNwMAIABBEGogAUEQaikDAEEgKQMAhTcDACAAQRhqIAFBGGopAwBBKCkDAIU3AwAgAEEgaiABQSBqKQMAQTApAwCFNwMAIABBKGogAUEoaikDAEE4KQMAhTcDACAAQTBqIAFBMGopAwBBwAApAwCFNwMAIABBOGogAUE4aikDAEHIACkDAIU3AwBBCEEIKQMAQgF8NwMAIABBwABqIQAgAUHAAGohASACQcAAayECDAALC0EIKQMAIQQgAkEASwRAQRBBAEHQABAFAkACQAJAAkACQAJAAkACQCACQQhuDgcHBgUEAwIBAAsgAEE4aiABQThqKQMAQcgAKQMAhTcDAAsgAEEwaiABQTBqKQMAQcAAKQMAhTcDAAsgAEEoaiABQShqKQMAQTgpAwCFNwMACyAAQSBqIAFBIGopAwBBMCkDAIU3AwALIABBGGogAUEYaikDAEEoKQMAhTcDAAsgAEEQaiABQRBqKQMAQSApAwCFNwMACyAAQQhqIAFBCGopAwBBGCkDAIU3AwALIAAgASkDAEEQKQMAhTcDAAtBEEIANwMAQRhCADcDAEEgQgA3AwBBKEIANwMAQTBCADcDAEE4QgA3AwBBwABCADcDAEHIAEIANwMAQdAAQgA3AwBB2ABCADcDAEHgAEIANwMAQegAQgA3AwAgBA8LnQUBEX9B5fDBiwYhA0HuyIGZAyEIQbLaiMsHIQ1B9MqB2QYhEiACKAIAIQQgAkEEaigCACEFIAJBCGooAgAhBiACQQxqKAIAIQcgAkEQaigCACEOIAJBFGooAgAhDyACQRhqKAIAIRAgAkEcaigCACERIAEoAgAhCSABQQRqKAIAIQogAUEIaigCACELIAFBDGooAgAhDEEUIRMCQANAIBNBAEYNASAHIAMgD2pBB3dzIQcgCyAHIANqQQl3cyELIA8gCyAHakENd3MhDyADIA8gC2pBEndzIQMgDCAIIARqQQd3cyEMIBAgDCAIakEJd3MhECAEIBAgDGpBDXdzIQQgCCAEIBBqQRJ3cyEIIBEgDSAJakEHd3MhESAFIBEgDWpBCXdzIQUgCSAFIBFqQQ13cyEJIA0gCSAFakESd3MhDSAGIBIgDmpBB3dzIQYgCiAGIBJqQQl3cyEKIA4gCiAGakENd3MhDiASIA4gCmpBEndzIRIgBCADIAZqQQd3cyEEIAUgBCADakEJd3MhBSAGIAUgBGpBDXdzIQYgAyAGIAVqQRJ3cyEDIAkgCCAHakEHd3MhCSAKIAkgCGpBCXdzIQogByAKIAlqQQ13cyEHIAggByAKakESd3MhCCAOIA0gDGpBB3dzIQ4gCyAOIA1qQQl3cyELIAwgCyAOakENd3MhDCANIAwgC2pBEndzIQ0gDyASIBFqQQd3cyEPIBAgDyASakEJd3MhECARIBAgD2pBDXdzIREgEiARIBBqQRJ3cyESIBNBAmshEwwACwsgACADNgIAIABBBGogCDYCACAAQQhqIA02AgAgAEEMaiASNgIAIABBEGogCTYCACAAQRRqIAo2AgAgAEEYaiALNgIAIABBHGogDDYCAAsKACAAIAEgAhAFC90GASF/QeXwwYsGIQNB7siBmQMhCEGy2ojLByENQfTKgdkGIRIgAigCACEEIAJBBGooAgAhBSACQQhqKAIAIQYgAkEMaigCACEHIAJBEGooAgAhDiACQRRqKAIAIQ8gAkEYaigCACEQIAJBHGooAgAhESABKAIAIQkgAUEEaigCACEKIAFBCGooAgAhCyABQQxqKAIAIQwgAyETIAQhFCAFIRUgBiEWIAchFyAIIRggCSEZIAohGiALIRsgDCEcIA0hHSAOIR4gDyEfIBAhICARISEgEiEiQRQhIwJAA0AgI0EARg0BIAcgAyAPakEHd3MhByALIAcgA2pBCXdzIQsgDyALIAdqQQ13cyEPIAMgDyALakESd3MhAyAMIAggBGpBB3dzIQwgECAMIAhqQQl3cyEQIAQgECAMakENd3MhBCAIIAQgEGpBEndzIQggESANIAlqQQd3cyERIAUgESANakEJd3MhBSAJIAUgEWpBDXdzIQkgDSAJIAVqQRJ3cyENIAYgEiAOakEHd3MhBiAKIAYgEmpBCXdzIQogDiAKIAZqQQ13cyEOIBIgDiAKakESd3MhEiAEIAMgBmpBB3dzIQQgBSAEIANqQQl3cyEFIAYgBSAEakENd3MhBiADIAYgBWpBEndzIQMgCSAIIAdqQQd3cyEJIAogCSAIakEJd3MhCiAHIAogCWpBDXdzIQcgCCAHIApqQRJ3cyEIIA4gDSAMakEHd3MhDiALIA4gDWpBCXdzIQsgDCALIA5qQQ13cyEMIA0gDCALakESd3MhDSAPIBIgEWpBB3dzIQ8gECAPIBJqQQl3cyEQIBEgECAPakENd3MhESASIBEgEGpBEndzIRIgI0ECayEjDAALCyAAIAMgE2o2AgAgAEEEaiAEIBRqNgIAIABBCGogBSAVajYCACAAQQxqIAYgFmo2AgAgAEEQaiAHIBdqNgIAIABBFGogCCAYajYCACAAQRhqIAkgGWo2AgAgAEEcaiAKIBpqNgIAIABBIGogCyAbajYCACAAQSRqIAwgHGo2AgAgAEEoaiANIB1qNgIAIABBLGogDiAeajYCACAAQTBqIA8gH2o2AgAgAEE0aiAQICBqNgIAIABBOGogESAhajYCACAAQTxqIBIgImo2AgAL");
  }
});

// wasm-module:./xsalsa20.wat
var bytes = require_xsalsa20();
var compiled = new WebAssembly.Module(bytes);
module.exports = (imports) => {
  const instance = new WebAssembly.Instance(compiled, imports);
  return instance.exports;
};

},{}],133:[function(require,module,exports){
const b4a = require('b4a')

const ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769'
const MIN = 0x31 // 1
const MAX = 0x7a // z
const REVERSE = new Int8Array(1 + MAX - MIN)

REVERSE.fill(-1)

for (let i = 0; i < ALPHABET.length; i++) {
  const v = ALPHABET.charCodeAt(i) - MIN
  REVERSE[v] = i
}

exports.encode = encode
exports.decode = decode

function decode (s, out) {
  let pb = 0
  let ps = 0

  const r = s.length & 7
  const q = (s.length - r) / 8

  if (!out) out = b4a.allocUnsafe(Math.ceil(s.length * 5 / 8))

  // 0 5 2 7 4 1 6 3 (+5 mod 8)
  for (let i = 0; i < q; i++) {
    const a = quintet(s, ps++)
    const b = quintet(s, ps++)
    const c = quintet(s, ps++)
    const d = quintet(s, ps++)
    const e = quintet(s, ps++)
    const f = quintet(s, ps++)
    const g = quintet(s, ps++)
    const h = quintet(s, ps++)

    out[pb++] = (a << 3) | (b >>> 2)
    out[pb++] = ((b & 0b11) << 6) | (c << 1) | (d >>> 4)
    out[pb++] = ((d & 0b1111) << 4) | (e >>> 1)
    out[pb++] = ((e & 0b1) << 7) | (f << 2) | (g >>> 3)
    out[pb++] = ((g & 0b111) << 5) | h
  }

  if (r === 0) return out.subarray(0, pb)

  const a = quintet(s, ps++)
  const b = quintet(s, ps++)

  out[pb++] = (a << 3) | (b >>> 2)

  if (r <= 2) return out.subarray(0, pb)

  const c = quintet(s, ps++)
  const d = quintet(s, ps++)

  out[pb++] = ((b & 0b11) << 6) | (c << 1) | (d >>> 4)

  if (r <= 4) return out.subarray(0, pb)

  const e = quintet(s, ps++)

  out[pb++] = ((d & 0b1111) << 4) | (e >>> 1)

  if (r <= 5) return out.subarray(0, pb)

  const f = quintet(s, ps++)
  const g = quintet(s, ps++)

  out[pb++] = ((e & 0b1) << 7) | (f << 2) | (g >>> 3)

  if (r <= 7) return out.subarray(0, pb)

  const h = quintet(s, ps++)

  out[pb++] = ((g & 0b111) << 5) | h

  return out.subarray(0, pb)
}

function encode (buf) {
  if (typeof buf === 'string') buf = b4a.from(buf)

  const max = buf.byteLength * 8

  let s = ''

  for (let p = 0; p < max; p += 5) {
    const i = p >>> 3
    const j = p & 7

    if (j <= 3) {
      s += ALPHABET[(buf[i] >>> (3 - j)) & 0b11111]
      continue
    }

    const of = j - 3
    const h = (buf[i] << of) & 0b11111
    const l = (i >= buf.byteLength ? 0 : buf[i + 1]) >>> (8 - of)

    s += ALPHABET[h | l]
  }

  return s
}

function quintet (s, i) {
  if (i > s.length) {
    return 0
  }

  const v = s.charCodeAt(i)

  if (v < MIN || v > MAX) {
    throw Error('Invalid character in base32 input: "' + s[i] + '" at position ' + i)
  }

  const bits = REVERSE[v - MIN]

  if (bits === -1) {
    throw Error('Invalid character in base32 input: "' + s[i] + '" at position ' + i)
  }

  return bits
}

},{"b4a":4}],134:[function(require,module,exports){
"use strict";

var Corestore = require("corestore");
module.exports = Corestore;

},{"corestore":19}]},{},[134])(134)
});
