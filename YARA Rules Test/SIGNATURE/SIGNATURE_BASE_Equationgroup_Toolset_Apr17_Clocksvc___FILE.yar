rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Clocksvc___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "ec0e90a5-1359-55e5-9165-494f90431247"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2787-L2807"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "04cdd8e4ca9df0231ca66caa8083eff1fe0834cdedc4360fce0a934970a6d162"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c1bcd04b41c6b574a5c9367b777efc8b95fe6cc4e526978b7e8e09214337fac1"

	strings:
		$x1 = "~debl00l.tmp" fullword ascii
		$x2 = "\\\\.\\mailslot\\c54321" fullword ascii
		$x3 = "\\\\.\\mailslot\\c12345" fullword ascii
		$x4 = "nowMutex" fullword ascii
		$s1 = "System\\CurrentControlSet\\Services\\MSExchangeIS\\ParametersPrivate" fullword ascii
		$s2 = "000000005017C31B7C7BCF97EC86019F5026BE85FD1FB192F6F4237B78DB12E7DFFB07748BFF6432B3870681D54BEF44077487044681FB94D17ED04217145B98" ascii
		$s3 = "00000000E2C9ADBD8F470C7320D28000353813757F58860E90207F8874D2EB49851D3D3115A210DA6475CCFC111DCC05E4910E50071975F61972DCE345E89D88" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and (1 of ($x*) or 2 of ($s*)))
}