import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Wineggdrop
{
	meta:
		description = "Disclosed hacktool set - file s.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "9b6244ee-5ace-5caa-bfa2-732bcfcfc998"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1171-L1194"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7665011742ce01f57e8dc0a85d35ec556035145d"
		logic_hash = "6123a07038e30e11e37a70b912a1c854c13341e67eaf4ed14ca9954288a42d62"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Normal Scan: About To Scan %u IP For %u Ports Using %d Thread" fullword ascii
		$s2 = "SYN Scan: About To Scan %u IP For %u Ports Using %d Thread" fullword ascii
		$s6 = "Example: %s TCP 12.12.12.12 12.12.12.254 21 512 /Banner" fullword ascii
		$s8 = "Something Wrong About The Ports" fullword ascii
		$s9 = "Performing Time: %d/%d/%d %d:%d:%d --> " fullword ascii
		$s10 = "Example: %s TCP 12.12.12.12/24 80 512 /T8 /Save" fullword ascii
		$s12 = "%u Ports Scanned.Taking %d Threads " fullword ascii
		$s13 = "%-16s %-5d -> \"%s\"" fullword ascii
		$s14 = "SYN Scan Can Only Perform On WIN 2K Or Above" fullword ascii
		$s17 = "SYN Scan: About To Scan %s:%d Using %d Thread" fullword ascii
		$s18 = "Scan %s Complete In %d Hours %d Minutes %d Seconds. Found %u Open Ports" fullword ascii

	condition:
		5 of them
}
