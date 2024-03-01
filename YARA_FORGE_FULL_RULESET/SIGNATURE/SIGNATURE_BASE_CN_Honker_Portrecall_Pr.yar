rule SIGNATURE_BASE_CN_Honker_Portrecall_Pr : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file pr"
		author = "Florian Roth (Nextron Systems)"
		id = "1e137ed0-3af6-5b01-a27b-87bf42359887"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_scripts.yar#L149-L165"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "583cf6dc2304121d835f2879803a22fea76930f3"
		logic_hash = "f33373e87887506651b1fac464f860a3cf18ad681ba124b606524f6f2255e693"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Usage: Same as lcx.exe in win32 :)" fullword ascii
		$s2 = "connect to client" fullword ascii
		$s3 = "PR(Packet redirection) for linux " fullword ascii

	condition:
		filesize <70KB and all of them
}
