rule SIGNATURE_BASE_CN_Honker__Lcx_Htran2_4_Htran20 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files lcx.exe, HTran2.4.exe, htran20.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c6851e7b-ab64-5578-896e-4d92fb3b2000"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L2446-L2465"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "30184394ad3ec7bf209bb0a22da889699bac6167ecc09e693c88f8643c754394"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "0c8779849d53d0772bbaa1cedeca150c543ebf38"
		hash1 = "524f986692f55620013ab5a06bf942382e64d38a"
		hash2 = "b992bf5b04d362ed3757e90e57bc5d6b2a04e65c"

	strings:
		$s1 = "[SERVER]connection to %s:%d error" fullword ascii
		$s2 = "[+] OK! I Closed The Two Socket." fullword ascii
		$s3 = "[+] Start Transmit (%s:%d <-> %s:%d) ......" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <440KB and all of them
}
