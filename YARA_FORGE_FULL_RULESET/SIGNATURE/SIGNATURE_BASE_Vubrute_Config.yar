import "pe"

rule SIGNATURE_BASE_Vubrute_Config
{
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file config.ini"
		author = "Florian Roth (Nextron Systems)"
		id = "25cad108-b2d6-5886-bb2f-e614e05649fa"
		date = "2014-11-22"
		modified = "2023-12-05"
		reference = "http://goo.gl/xiIphp"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1493-L1513"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b9f66b9265d2370dab887604921167c11f7d93e9"
		logic_hash = "b4c54d5ecb269c7310b5bd2a9e8fe5d6c75503f8cb1f25679399e25185d9cb51"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "Restore=1" fullword ascii
		$s6 = "Thread=" ascii
		$s7 = "Running=1" fullword ascii
		$s8 = "CheckCombination=" fullword ascii
		$s10 = "AutoSave=1.000000" fullword ascii
		$s12 = "TryConnect=" ascii
		$s13 = "Tray=" ascii

	condition:
		all of them
}
