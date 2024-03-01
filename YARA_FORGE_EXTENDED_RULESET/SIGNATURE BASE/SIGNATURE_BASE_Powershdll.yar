rule SIGNATURE_BASE_Powershdll
{
	meta:
		description = "Detects hack tool PowerShdll"
		author = "Florian Roth (Nextron Systems)"
		id = "cc0e01ca-77f0-5665-8b1e-48c8e947d0d3"
		date = "2017-08-03"
		modified = "2023-12-05"
		reference = "https://github.com/p3nt4/PowerShdll"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_powershdll.yar#L9-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6c93eca642cc29e6ce661e6ea975bc1a88fff4e6a4825c1da3f82b3a6701392a"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4d33bc7cfa79d7eefc5f7a99f1b052afdb84895a411d7c30045498fd4303898a"
		hash2 = "f999db9cc3a0719c19f35f0e760f4ce3377b31b756d8cd91bb8270acecd7be7d"

	strings:
		$x1 = "rundll32 PowerShdll,main -f <path>" fullword wide
		$x2 = "\\PowerShdll.dll" ascii
		$x3 = "rundll32 PowerShdll,main <script>" fullword wide

	condition:
		1 of them
}
