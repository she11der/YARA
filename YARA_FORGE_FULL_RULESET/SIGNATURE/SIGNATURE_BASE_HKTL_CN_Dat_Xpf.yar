rule SIGNATURE_BASE_HKTL_CN_Dat_Xpf : FILE
{
	meta:
		description = "Chinese Hacktool Set - file xpf.sys"
		author = "Florian Roth (Nextron Systems)"
		id = "fe2de535-4f86-5c29-b67e-153423a897f7"
		date = "2015-06-13"
		modified = "2023-01-06"
		old_rule_name = "dat_xpf"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L880-L897"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "761125ab594f8dc996da4ce8ce50deba49c81846"
		logic_hash = "c46b10ef17a9fee2be15fc9cc8b8aeec94d656b86e7208e1ad1f5efcd95fddf5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "UnHook IoGetDeviceObjectPointer ok!" fullword ascii
		$s2 = "\\Device\\XScanPF" wide
		$s3 = "\\DosDevices\\XScanPF" wide

	condition:
		uint16(0)==0x5a4d and filesize <25KB and all of them
}
