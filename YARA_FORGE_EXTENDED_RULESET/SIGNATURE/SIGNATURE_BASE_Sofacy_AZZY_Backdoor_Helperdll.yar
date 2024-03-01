rule SIGNATURE_BASE_Sofacy_AZZY_Backdoor_Helperdll : FILE
{
	meta:
		description = "Dropped C&C helper DLL for AZZY 4.3"
		author = "Florian Roth (Nextron Systems)"
		id = "eae089a0-21dc-5d6e-a4bc-7181dc9b8b35"
		date = "2015-12-04"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sofacy_dec15.yar#L61-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "6cd30c85dd8a64ca529c6eab98a757fb326de639a39b597414d5340285ba91c6"
		logic_hash = "100903551eeacf4266fc97a09949bdafe05e94698bed7cea295c8e970df22ec8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "snd.dll" fullword ascii
		$s1 = "InternetExchange" fullword ascii
		$s2 = "SendData"

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
