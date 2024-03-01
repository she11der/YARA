rule MALPEDIA_Win_Infy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "57c24fda-e429-5a88-80d2-235251d4052e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.infy"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.infy_auto.yar#L1-L122"
		license_url = "N/A"
		logic_hash = "97f3b09f4f39ef998f79ec8093433c607a41cb99a12ab0573691bf5dec73bf57"
		score = 60
		quality = 45
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
		$sequence_0 = { 7e24 8945d4 807de300 7409 8b45e4 66833820 }
		$sequence_1 = { 7409 8b13 8bc3 e8???????? 85c0 7405 83e804 }
		$sequence_2 = { 57 33c9 894df8 8955f0 }
		$sequence_3 = { 7553 837e1400 7442 837e1c00 }
		$sequence_4 = { 668378f602 7412 6a00 89e0 }
		$sequence_5 = { 68???????? 8d45c8 ba09000000 e8???????? 8d45ec }
		$sequence_6 = { 807de300 7409 8b45e4 66833820 7304 33c0 eb02 }
		$sequence_7 = { c1e002 034610 f6400380 0f94c2 83e201 8955e0 85d2 }
		$sequence_8 = { e8???????? 8bd0 81e2ff000000 2500ff0000 c1e808 83fa05 7505 }
		$sequence_9 = { e8???????? 83c40c 5b 5d c20800 55 8bec }

	condition:
		7 of them and filesize <147456
}
