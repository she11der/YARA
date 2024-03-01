rule SIGNATURE_BASE_Regin_Sample_3 : FILE
{
	meta:
		description = "Detects Regin Backdoor sample fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"
		author = "@Malwrsignatures"
		id = "eefc174f-4b17-5c90-8478-3eaaf80e9a78"
		date = "2014-11-27"
		modified = "2023-12-15"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_regin_fiveeyes.yar#L204-L229"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"
		logic_hash = "5a0f77f203765f7737c00c3df760ea7f3ed354559aad07f3053173ff09e1ce1a"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "Service Pack x" fullword wide
		$s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" wide
		$s2 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\HotFix" wide
		$s3 = "mntoskrnl.exe" fullword wide
		$s4 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management" wide
		$s5 = "Memory location: 0x%p, size 0x%08x" wide fullword
		$s6 = "Service Pack" fullword wide
		$s7 = ".sys" fullword wide
		$s8 = ".dll" fullword wide
		$s10 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Updates" wide
		$s11 = "IoGetRelatedDeviceObject" fullword ascii
		$s12 = "VMEM.sys" fullword ascii
		$s13 = "RtlGetVersion" fullword wide
		$s14 = "ntkrnlpa.exe" fullword ascii

	condition:
		uint32(0)==0xfedcbafe and all of ($s*) and filesize >160KB and filesize <200KB
}
