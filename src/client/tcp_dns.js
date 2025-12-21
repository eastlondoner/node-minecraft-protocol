const dns = require('dns')

/**
 * TCP/DNS connection setup for Bun-native client.
 * Handles SRV record lookups for Minecraft servers.
 * Supports mTLS via options.tls configuration.
 */
module.exports = function (client, options) {
  options.port = options.port || 25565
  options.host = options.host || 'localhost'

  if (!options.connect) {
    options.connect = (client) => {
      // Custom streams not supported in Bun-native implementation
      if (options.stream) {
        throw new Error('Custom streams not supported - use Bun.connect directly')
      }

      const { host, port, tls } = options
      
      // Check if host is an IP address (IPv4 or IPv6)
      const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':')
      
      // SRV lookup for non-IP, non-localhost hosts on default port (skip if TLS enabled)
      if (!tls && port === 25565 && !isIP && host !== 'localhost') {
        dns.resolveSrv('_minecraft._tcp.' + host, (err, addresses) => {
          if (!err && addresses?.length > 0) {
            options.host = addresses[0].name
            options.port = addresses[0].port
            client.connect(addresses[0].port, addresses[0].name, tls)
          } else {
            client.connect(port, host, tls)
          }
        })
      } else {
        client.connect(port, host, tls)
      }
    }
  }
}
