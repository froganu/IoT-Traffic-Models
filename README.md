# IoT-Traffic-Models
Contexts:
TLS 1.2 to TLS 1.3-enabled Malware
MQTT, COAP:v1, RTSP
Different mirai attacks on Danmini Doorbell Device	
Mirai attacks to IoT devices in CICIOT lab
DNS-Based Command & Control

Packets:
Encrypted - TLS/Quic/DTLS
Not Encrypted 

MoE - Multiple of Experts

1- check if encrypted - deterministic tool
2- if:
	encrypted - we use the TLS AI model, deterministic decision (ideal - AI model that decides QUIC vs TLS vs DTLS) - check if DNS traffic can be recognize when encrypted.
	not encrypted -  we use AI model(the selector) to recognize the not encrypted context and run the matching expert, it will include 2 classifications, device based and protocol based

Infrastructure:
Table of accuracy per context/AI model
Trained AI models

Enhancements - 
Result of best 2 for each context
Light retraining DPI
	
