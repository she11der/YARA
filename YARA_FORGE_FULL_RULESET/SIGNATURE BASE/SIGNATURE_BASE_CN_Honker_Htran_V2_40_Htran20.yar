rule SIGNATURE_BASE_CN_Honker_Htran_V2_40_Htran20 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file htran20.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "9dd1ab4b-108e-55be-b94d-2868ce00855e"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1137-L1156"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b992bf5b04d362ed3757e90e57bc5d6b2a04e65c"
		logic_hash = "41a85430875df622e7940ef26c6eceaa4e0720b2995521fbb2d4b072207c8e15"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%s -slave  ConnectHost ConnectPort TransmitHost TransmitPort" fullword ascii
		$s2 = "Enter Your Socks Type No: [0.BindPort 1.ConnectBack 2.Listen]:" fullword ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "%s -connect ConnectHost [ConnectPort]       Default:%d" fullword ascii
		$s5 = "[+] got, ip:%s, port:%d" fullword ascii
		$s6 = "[-] There is a error...Create a new connection." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
