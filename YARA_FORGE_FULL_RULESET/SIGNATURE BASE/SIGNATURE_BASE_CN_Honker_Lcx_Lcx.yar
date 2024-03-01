rule SIGNATURE_BASE_CN_Honker_Lcx_Lcx : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - HTRAN - file lcx.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "6c2e1e85-6387-5be2-b7b2-5ae8a5cca6df"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L970-L988"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0c8779849d53d0772bbaa1cedeca150c543ebf38"
		logic_hash = "6e81cac14baa9f0ae35eb26f30291cba6f7ef1864f8970b97a3e6e7205d10eb9"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
		$s2 = "=========== Code by lion & bkbll" ascii
		$s3 = "Welcome to [url]http://www.cnhonker.com[/url] " ascii
		$s4 = "-tran   <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s5 = "[+] Start Transmit (%s:%d <-> %s:%d) ......" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and 1 of them
}
