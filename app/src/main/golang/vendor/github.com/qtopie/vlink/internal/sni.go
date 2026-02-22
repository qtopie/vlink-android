package internal

import (
	"encoding/binary"
	"errors"
)

// ParseSNI attempts to extract the Server Name Indication (SNI) from the beginning of a TLS ClientHello.
// data should contain the initial bytes of the connection (at least enough for the ClientHello header).
func ParseSNI(data []byte) (string, error) {
	// TLS Record Header (5 bytes)
	// Content Type (1) + Version (2) + Length (2)
	if len(data) < 5 {
		return "", errors.New("data too short")
	}

	// Content Type: Handshake (22)
	if data[0] != 22 {
		return "", errors.New("not a TLS handshake")
	}

	// Handshake Type: Client Hello (1)
	// Skip Record Header (5)
	rest := data[5:]
	if len(rest) < 4 {
		return "", errors.New("data too short for handshake header")
	}

	if rest[0] != 1 {
		return "", errors.New("not a client hello")
	}

	// Handshake Length (3 bytes)
	// handshakeLen := int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3])
	rest = rest[4:]

	// Client Version (2) + Random (32)
	if len(rest) < 34 {
		return "", errors.New("data too short for body")
	}
	rest = rest[34:]

	// Session ID
	if len(rest) < 1 {
		return "", errors.New("data too short for session id")
	}
	sessionIdLen := int(rest[0])
	rest = rest[1:]
	if len(rest) < sessionIdLen {
		return "", errors.New("data too short for session id body")
	}
	rest = rest[sessionIdLen:]

	// Cipher Suites
	if len(rest) < 2 {
		return "", errors.New("data too short for cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if len(rest) < cipherSuitesLen {
		return "", errors.New("data too short for cipher suites")
	}
	rest = rest[cipherSuitesLen:]

	// Compression Methods
	if len(rest) < 1 {
		return "", errors.New("data too short for compression methods length")
	}
	compressionMethodsLen := int(rest[0])
	rest = rest[1:]
	if len(rest) < compressionMethodsLen {
		return "", errors.New("data too short for compression methods")
	}
	rest = rest[compressionMethodsLen:]

	// Extensions
	if len(rest) < 2 {
		// No extensions
		return "", errors.New("no extensions")
	}
	extensionsLen := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if len(rest) < extensionsLen {
		return "", errors.New("data too short for extensions")
	}
	extensions := rest[:extensionsLen]

	// Parse Extensions
	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions)
		extLen := int(binary.BigEndian.Uint16(extensions[2:]))
		extensions = extensions[4:]

		if len(extensions) < extLen {
			break
		}
		extData := extensions[:extLen]
		extensions = extensions[extLen:]

		// SNI Extension Type is 0
		if extType == 0 {
			// SNI Structure:
			// List Length (2)
			// Type (1) + Length (2) + Name (Length)
			if len(extData) < 2 {
				continue
			}
			listLen := int(binary.BigEndian.Uint16(extData))
			if listLen+2 != len(extData) {
				continue // Malformed
			}
			extData = extData[2:]

			for len(extData) > 0 {
				if len(extData) < 3 {
					break
				}
				nameType := extData[0]
				nameLen := int(binary.BigEndian.Uint16(extData[1:]))
				extData = extData[3:]
				if len(extData) < nameLen {
					break
				}

				// Host Name Type is 0
				if nameType == 0 {
					return string(extData[:nameLen]), nil
				}
				extData = extData[nameLen:]
			}
		}
	}

	return "", errors.New("sni not found")
}
