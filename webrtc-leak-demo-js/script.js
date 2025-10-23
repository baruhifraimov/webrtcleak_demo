// 23102025.0017
// This regex is designed to match all standard IPv4 formats.
const regexIPv4 = /\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
// This is a more comprehensive regex for IPv6 that handles various formats including compressed ones.
const regexIPv6 = /((([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])))(?=\s|\b)/gi;

/**
 * Module to send the log content to the backend server.
 * @param {string} content - The text content to send.
 */
const logToServer = async (content) => {
  try {
    // This sends the data to the '/api/log' path, which Apache will proxy to our backend.
    const response = await fetch('/api/log', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ logContent: content }),
    });
    if (response.ok) {
      console.log('Log successfully sent to the server.');
    } else {
      console.error('Failed to send log to the server:', response.statusText);
    }
  } catch (error) {
    console.error('Error sending log to the server:', error);
  }
};

/**
 * Module to fetch geolocation data for a given IP address.
 * @param {string} ip - The IP address to look up.
 * @returns {Promise<object>} - A promise that resolves with the geo data.
 */
const getGeoData = async (ip) => {
  try {
    // Using ipapi.co which is more reliable and has better CORS support
    const response = await fetch(`https://ipapi.co/${ip}/json/`);
    if (!response.ok) {
      const errorText = await response.text();
      return { error: `Failed to fetch GeoIP for ${ip}. Status: ${response.status}. Details: ${errorText}` };
    }
    const data = await response.json();
    return {
      country: data.country_name || 'Unknown',
      city: data.city || 'Unknown',
      postal_code: data.postal || 'Unknown',
      time_zone: data.timezone || 'Unknown',
      latitude: data.latitude || 'Unknown',
      longitude: data.longitude || 'Unknown',
      isVPN: data.hosting || false, // If it's a hosting provider, likely a VPN/proxy
      org: data.org || 'Unknown', // Added organization info which can help identify VPN providers
      asn: data.asn || 'Unknown' // Added ASN which can help identify the network provider
    };
  } catch (error) {
    console.error('GeoIP Error:', error);
    return { error: `Error fetching GeoIP: ${error.message}` };
  }
};

/**
 * Checks if an IP address is a private/local address.
 * @param {string} ip The IP address to check.
 * @returns {boolean} True if the IP is private.
 */
const isPrivateIP = (ip) => {
  if (regexIPv4.test(ip)) {
    const parts = ip.split('.').map(part => parseInt(part, 10));
    return parts[0] === 10 ||
           (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
           (parts[0] === 192 && parts[1] === 168);
  }
  // Reset regex state for the next test
  regexIPv6.lastIndex = 0;
  if (regexIPv6.test(ip)) {
    // Check for private IPv6 ranges (e.g., fc00::/7 for Unique Local Addresses)
    return ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd');
  }
  return false;
};


/**
 * The main function to perform the WebRTC leak test and log the results.
 * @param {number} timeout - The time in milliseconds to wait for ICE candidates.
 */
const runLeakTest = async (timeout = 5000) => {
  console.log('Starting WebRTC leak test with improved logic...');
  const uniqueLeakedIPs = new Set();
  const iceCandidateTypes = { host: 0, srflx: 0, relay: 0 };
  const localHostnames = new Set();

  const onicecandidate = (ice) => {
    const candidate = ice?.candidate?.candidate;
    if (candidate) {
      console.log('ICE candidate received:', candidate);
      // Extract candidate type
      const typeMatch = candidate.match(/typ ([a-z]+)/);
      if (typeMatch && typeMatch[1]) {
        iceCandidateTypes[typeMatch[1]] = (iceCandidateTypes[typeMatch[1]] || 0) + 1;
      }
      
      // Check for mDNS hostnames
      if (candidate.includes('.local ')) {
        const hostnameMatch = candidate.match(/([a-f0-9-]+\.local)/);
        if (hostnameMatch) {
          localHostnames.add(hostnameMatch[1]);
        }
      }

      // Extract all IPs from the candidate string
      const ips = candidate.match(new RegExp(`${regexIPv4.source}|${regexIPv6.source}`, 'g'));
      if (ips) {
        ips.forEach(ip => {
          console.log('Detected IP:', ip);
          uniqueLeakedIPs.add(ip);
        });
      }
    }
  };

  const RTCPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;

  if (!RTCPeerConnection) {
    console.error('WebRTC is not supported by this browser.');
    await logToServer('WebRTC is not supported by this browser.');
    return;
  }

  // Using local STUN server with authentication
  const iceServers = [{
    urls: ['stun:192.168.2.135:3478','stun:77.125.137.213:3478', 'stun:[2001:db8::1]:3478', 'stun:stun.l.google.com:19302']
  }];

  const connection = new RTCPeerConnection({ 
    iceServers,
    iceTransportPolicy: 'all',
    rtcpMuxPolicy: 'require',
    iceCandidatePoolSize: 1
  });

  connection.addEventListener('icecandidate', onicecandidate);
  connection.createDataChannel('');
  try {
    const offer = await connection.createOffer();
    await connection.setLocalDescription(offer);
  } catch (e) {
    console.error('Error creating WebRTC offer:', e);
  }

  // Wait for the timeout to collect IPs
  setTimeout(async () => {
    try {
      connection.removeEventListener('icecandidate', onicecandidate);
      connection.close();
    } catch {}

    // --- Start Data Collection ---
    console.log('Collecting data for server log...');

    // 1. Get Public IP from a reliable source
    let primaryPublicIp = 'Unknown';
    try {
      const response = await fetch('https://api.ipify.org?format=json');
      const data = await response.json();
      primaryPublicIp = data.ip;
    } catch (e) {
      console.error('Could not fetch primary public IP.', e);
    }

    // 2. Get Advanced Browser Fingerprint
    const fingerprint = {};
    const nav = window.navigator;
    const properties = [
        'userAgent', 'language', 'languages', 'platform', 'hardwareConcurrency', 
        'deviceMemory', 'doNotTrack', 'cookieEnabled', 'maxTouchPoints', 'vendor',
        'product', 'productSub', 'vendorSub', 'oscpu', 'buildID', 'appCodeName',
        'appName', 'appVersion', 'pdfViewerEnabled', 'webdriver', 'globalPrivacyControl'
    ];
    properties.forEach(prop => {
        try {
            if (prop in nav) {
                fingerprint[prop] = nav[prop];
            }
        } catch (e) { /* ignore inaccessible properties */ }
    });

    // Get precise timezone info
    try {
        fingerprint.timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        fingerprint.utcOffset = -new Date().getTimezoneOffset() / 60;
    } catch (e) {
        console.error('Error getting timezone:', e);
    }

    // Canvas fingerprint
    try {
        const canvas = document.createElement('canvas');
        canvas.width = 300;
        canvas.height = 150;
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('Fingerprint!', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('Canvas Test', 4, 45);
        fingerprint.canvasHash = canvas.toDataURL();
    } catch (e) {
        console.error('Error getting canvas fingerprint:', e);
    }

    // WebGL fingerprint
    try {
        const gl = document.createElement('canvas').getContext('webgl');
        if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
                fingerprint.gpuVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                fingerprint.gpuRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            }
        }
    } catch (e) {
        console.error('Error getting WebGL info:', e);
    }

    // Audio fingerprint
    try {
        const audioCtx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 44100, 44100);
        const oscillator = audioCtx.createOscillator();
        oscillator.type = 'triangle';
        oscillator.frequency.setValueAtTime(10000, audioCtx.currentTime);
        const compressor = audioCtx.createDynamicsCompressor();
        oscillator.connect(compressor);
        compressor.connect(audioCtx.destination);
        oscillator.start(0);
        audioCtx.startRendering().then(buffer => {
            const data = buffer.getChannelData(0).slice(4500, 5000);
            fingerprint.audioHash = data.reduce((acc, val) => acc + Math.abs(val), 0).toString();
        });
    } catch (e) {
        console.error('Error getting audio fingerprint:', e);
    }

    // Media Devices
    if (navigator.mediaDevices?.enumerateDevices) {
        navigator.mediaDevices.enumerateDevices()
            .then(devices => {
                fingerprint.mediaDevices = {
                    audioInputs: devices.filter(d => d.kind === 'audioinput').length,
                    audioOutputs: devices.filter(d => d.kind === 'audiooutput').length,
                    videoInputs: devices.filter(d => d.kind === 'videoinput').length
                };
            })
            .catch(e => console.error('Error enumerating devices:', e));
    }

    // Network Information
    if (navigator.connection) {
        fingerprint.networkInfo = {
            type: navigator.connection.effectiveType,
            downlink: navigator.connection.downlink,
            rtt: navigator.connection.rtt
        };
    }


    // 3. Consolidate and get GeoData for all unique IPs
    const allUniqueIps = new Set([primaryPublicIp, ...uniqueLeakedIPs].filter(ip => ip && ip !== 'Unknown'));
    const geoDataPromises = [...allUniqueIps].map(ip => getGeoData(ip).then(data => ({ ip, ...data })));
    const geoResults = await Promise.all(geoDataPromises);

    // --- Format Log Content ---
    const now = new Date();
    const localDateTime = now.toLocaleString('en-US', { 
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        fractionalSecondDigits: 3,
        hour12: false
    });
    let logContent = `--- New Client Entry: ${localDateTime} (Local Time) ---\n`;
    logContent += `User Agent: ${navigator.userAgent}\n\n`;
    
    logContent += '--- WebRTC Information ---\n';
    logContent += `ICE Candidate Types: ${JSON.stringify(iceCandidateTypes)}\n`;
    if (localHostnames.size > 0) {
        logContent += `mDNS Hostnames: ${Array.from(localHostnames).join(', ')}\n`;
    }
    
    logContent += '\n--- IP Information ---\n';
    geoResults.forEach(geo => {
        let ipType = 'Leaked';
        if (geo.ip === primaryPublicIp) {
            ipType = 'Public (Primary)';
        } else if (isPrivateIP(geo.ip)) {
            ipType = 'Local (Private)';
        }

        logContent += `IP: ${geo.ip}\n`;
        logContent += `  - Type: ${ipType}\n`;
        if (geo.isVPN) {
            logContent += `  - Note: This IP may be a VPN/Proxy.\n`;
        }
        logContent += `  - Country: ${geo.country}\n`;
        logContent += `  - City: ${geo.city}\n`;
        logContent += `  - Postal Code: ${geo.postal_code}\n`;
        logContent += `  - Time Zone: ${geo.time_zone}\n`;
        logContent += `  - Coordinates: ${geo.latitude}, ${geo.longitude}\n\n`;
    });

    logContent += '--- Browser Fingerprint ---\n';
    logContent += JSON.stringify(fingerprint, null, 2);
    
    // Send the final report to the backend server
    await logToServer(logContent);
    console.log('Leak test finished. Log sent to server.');
  }, timeout);
};

// Autorun the test when the script loads
runLeakTest();
