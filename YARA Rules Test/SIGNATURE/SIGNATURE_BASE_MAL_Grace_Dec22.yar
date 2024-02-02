rule SIGNATURE_BASE_MAL_Grace_Dec22
{
	meta:
		description = "Detects Grace (aka FlawedGrace and GraceWire) RAT"
		author = "X__Junior"
		id = "fc2214dc-f1e5-52d7-a9de-88709a03b04e"
		date = "2022-12-13"
		modified = "2023-12-05"
		reference = "https://blog.talosintelligence.com/breaking-the-silence-recent-truebot-activity/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/expl_sysaid_cve_2023_47246.yar#L40-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "8276662dadfa2f8e07dd7882a60e55bd22ecf1f8f66a09940f16236598646560"
		score = 70
		quality = 85
		tags = ""
		hash1 = "a66df3454b8c13f1b92d8b2cf74f5bfcdedfbff41a5e4add62e15277d14dd169"
		hash2 = "e113a8df3c4845365f924bacf10c00bcc5e17587a204b640852dafca6db20404"

	strings:
		$sa1 = "Grace finalized, no more library calls allowed." ascii
		$sa2 = "Socket forcibly closed due to no response to DISCONNECT signal from other side, worker id(%d)" ascii
		$sa3 = "AVWireCleanupThread" ascii
		$sa4 = "AVTunnelClientDirectIO" ascii
		$sa5 = "AVGraceTunnelWriteThread" ascii
		$sa6 = "AVGraceTunnelClientDirectIO" ascii

	condition:
		2 of them
}