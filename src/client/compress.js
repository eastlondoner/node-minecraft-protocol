/**
 * Handle compression negotiation with server.
 * Compression is handled inline in the Bun-native client.
 */
module.exports = function (client, options) {
  client.once('compress', onCompressionRequest)
  client.on('set_compression', onCompressionRequest)

  function onCompressionRequest (packet) {
    client.compressionThreshold = packet.threshold
  }
}
