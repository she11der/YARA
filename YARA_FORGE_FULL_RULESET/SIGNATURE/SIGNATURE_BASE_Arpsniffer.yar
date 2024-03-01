rule SIGNATURE_BASE_Arpsniffer : FILE
{
	meta:
		description = "Chinese Hacktool Set - file arpsniffer.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "78db3b18-008a-5a4e-9504-0cbe3b852046"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1489-L1506"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7d8753f56fc48413fc68102cff34b6583cb0066c"
		logic_hash = "eb0a425be0fff87eb58689a4eee4b6729e8ee985e6224790111322d4b182caf1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "SHELL" ascii
		$s2 = "PacketSendPacket" fullword ascii
		$s3 = "ArpSniff" ascii
		$s4 = "pcap_loop" fullword ascii
		$s5 = "packet.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <120KB and all of them
}
