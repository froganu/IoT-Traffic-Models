# IoT-Traffic-Models
Contexts:
<br>
TLS 1.2 to TLS 1.3-enabled Malware
<br>
MQTT, COAP:v1, RTSP
<br>
Different mirai attacks on Danmini Doorbell Device	
<br>
Mirai attacks to IoT devices in CICIOT lab
<br>
DNS-Based Command & Control
<br>
<br>
Packets:
<br>
Encrypted - TLS/Quic/DTLS
<br>
Not Encrypted 
<br>
<br>
MoE - Multiple of Experts
<br>
<br>
1- check if encrypted - deterministic tool
<br>
2- if:
<br>
	encrypted - we use the TLS AI model, deterministic decision (ideal - AI model that decides QUIC vs TLS vs DTLS) - check if DNS traffic can be recognize when encrypted.
	<br>
	not encrypted -  we use AI model(the selector) to recognize the not encrypted context and run the matching expert, it will include 2 classifications, device based and protocol based
	<br>
<br>
Infrastructure:
<br>
Table of accuracy per context/AI model
<br>
Trained AI models
<br>
<br>
Enhancements - 
<br>
Result of best 2 for each context
<br>
Light retraining DPI
<br>
	
