rule SIGNATURE_BASE_Dll_Packetx : FILE
{
	meta:
		description = "Chinese Hacktool Set - file PacketX.dll - ActiveX wrapper for WinPcap packet capture library"
		author = "Florian Roth (Nextron Systems)"
		id = "19ab5977-934d-5e3f-8bba-925bb57bf486"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L181-L196"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3f0908e0a38512d2a4fb05a824aa0f6cf3ba3b71"
		logic_hash = "161d174376c599b1b794fa1174349ae12b198842d89769baec4b9664729a3983"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s9 = "[Failed to load winpcap packet.dll." wide
		$s10 = "PacketX Version" wide

	condition:
		uint16(0)==0x5a4d and filesize <1920KB and all of them
}
