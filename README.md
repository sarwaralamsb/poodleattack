# POODLE Attack: Investigating SSLv3 Vulnerabilities

The Secure Socket Layer (SSL) protocol was initially developed to secure data transmission but has undergone several updates due to vulnerabilities, such as the POODLE attack. SSL versions 1.0, 2.0, and 3.0 faced various issues, leading to the development of the more secure Transport Layer Security (TLS) protocol.

However, to maintain compatibility, TLS was designed to be backward-compatible with SSL. This compatibility allowed the POODLE attack to exploit the downgrade behavior, enabling attackers to decrypt SSLv3 communications via a man-in-the-middle attack. Despite the limited attack vectors, SSLv3 remains vulnerable, and its use is now restricted in most modern systems. 

This project delves into the POODLE attack, providing a detailed overview of its mechanisms, impact, and the evolution of SSL/TLS protocols to mitigate such vulnerabilities.
