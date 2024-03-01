import "pe"

rule SIGNATURE_BASE_Ikat_Command_Lines_Agent
{
	meta:
		description = "iKAT hack tools set agent - file ikat.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "35068d59-272d-55a6-b211-2c138276914c"
		date = "2014-05-11"
		modified = "2023-12-05"
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L843-L864"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c802ee1e49c0eae2a3fc22d2e82589d857f96d94"
		logic_hash = "a39f8e388aa11c732156753f4a19aa9cc3ccd0437de30cdcc608926320a089b0"
		score = 75
		quality = 60
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Extended Module: super mario brothers" fullword ascii
		$s1 = "Extended Module: " fullword ascii
		$s3 = "ofpurenostalgicfeeling" fullword ascii
		$s8 = "-supermariobrotheretic" fullword ascii
		$s9 = "!http://132.147.96.202:80" fullword ascii
		$s12 = "iKAT Exe Template" fullword ascii
		$s15 = "withadancyflavour.." fullword ascii
		$s16 = "FastTracker v2.00   " fullword ascii

	condition:
		4 of them
}
