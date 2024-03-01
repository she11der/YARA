rule SIGNATURE_BASE_Ghostdragon_Gh0Strat_Sample3
{
	meta:
		description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
		author = "Florian Roth (Nextron Systems)"
		id = "6d4bb99d-28de-59c2-b6f0-6da3cac4ed73"
		date = "2016-04-23"
		modified = "2023-12-05"
		reference = "https://blog.cylance.com/the-ghost-dragon"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_ghostdragon_gh0st_rat.yar#L77-L92"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "39ddb94ac14032f88e54e413ed650277e95f6dcf66219fcf43a01aff1f10a058"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1be9c68b31247357328596a388010c9cfffadcb6e9841fb22de8b0dc2d161c42"

	strings:
		$op1 = { 44 24 15 65 88 54 24 16 c6 44 24 }
		$op2 = { 44 24 1b 43 c6 44 24 1c 75 88 54 24 1e }
		$op3 = { 1e 79 c6 44 24 1f 43 c6 44 24 20 75 88 54 24 22 }

	condition:
		all of them
}
