import "pe"

rule SIGNATURE_BASE_Sig_238_Letmein
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file letmein.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "5dba055f-1928-534a-8d0e-11dda56d93b7"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1659-L1675"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "74d223a56f97b223a640e4139bb9b94d8faa895d"
		logic_hash = "6cf454d11bc806b3a30c52b730994adb8d92613c92849162717f415e5681e417"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Error get globalgroup memebers: NERR_InvalidComputer" fullword ascii
		$s6 = "Error get users from server!" fullword ascii
		$s7 = "get in nt by name and null" fullword ascii
		$s16 = "get something from nt, hold by killusa." fullword ascii

	condition:
		all of them
}
