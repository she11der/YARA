rule MALPEDIA_Win_Blackmagic_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "dd528f6f-030a-5c0c-abc0-3a9e54fb0bef"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackmagic"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.blackmagic_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "9b47417ce0472639cee5ef75e6c79509f45487b7ad058f003aa41d6f30ea451f"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 488d15b40c0700 488bcd e8???????? 488b4620 488903 488b5c2430 488b6c2438 }
		$sequence_1 = { 4c8b01 ba01000000 41ff10 90 488bc7 488b4c2458 4833cc }
		$sequence_2 = { 4863d0 488d4dd0 488b94d3086c0700 e8???????? 488b0d???????? 0fbe01 }
		$sequence_3 = { 3bc3 740a 8b5c245c 85db 748d eb35 ff15???????? }
		$sequence_4 = { 48895e08 488b4718 4c894010 488b4718 49894018 4c894718 49897810 }
		$sequence_5 = { 0f114160 0f104070 488b8090000000 0f114170 0f118980000000 48898190000000 488d0587eaffff }
		$sequence_6 = { 0f867d030000 458d7302 448d7d02 8bc5 4c8d1483 418b3a }
		$sequence_7 = { 41f782b800000000080000 7427 498b8ad0000000 410fb6d3 e8???????? 440fb65c2430 0fbec8 }
		$sequence_8 = { 488bd0 e8???????? 488b5308 498bce 482b13 48c1fa02 e8???????? }
		$sequence_9 = { 4881f900100000 7223 488d4127 483bc1 0f8681000000 488bc8 e8???????? }

	condition:
		7 of them and filesize <1416192
}
