rule MALPEDIA_Win_Strelastealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "308b6312-f55e-5e44-8b26-8341d0a5504a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.strelastealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.strelastealer_auto.yar#L1-L169"
		license_url = "N/A"
		logic_hash = "4a18fbcab2ec145e1ed1c3a8aa2118c83ff2631df0db61e9cbe03afa397c02a3"
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
		$sequence_0 = { 0f85e6030000 6804010000 8d942464010000 53 52 e8???????? }
		$sequence_1 = { ff15???????? 8b442434 8b4c2438 53 }
		$sequence_2 = { 488945f0 488d15d8a20000 b805000000 894520 }
		$sequence_3 = { 885909 b801000000 83c404 51 0fb69220a30010 3011 33d2 }
		$sequence_4 = { ff15???????? 33c9 8be8 85db 7612 8bc1 }
		$sequence_5 = { 48895c2408 4889742410 57 4c8bd2 488d351b43ffff }
		$sequence_6 = { 488d442478 33d2 4889442430 c744242801000000 4c897c2420 }
		$sequence_7 = { 488d15eba10000 488d0dc4a10000 e8???????? 488d15e8a10000 488d0dd9a10000 }
		$sequence_8 = { 0f85bc030000 8b442414 53 53 53 53 8d54244c }
		$sequence_9 = { 740d 488bc8 49878cff20ac0100 eb0a 4d87b4ff20ac0100 33c0 }
		$sequence_10 = { 4c8d05c7680100 c744243000020080 488d1548690100 48897c2428 4533c9 }
		$sequence_11 = { 53 4883ec20 488d057f740000 488bd9 483bc8 7418 }
		$sequence_12 = { 488d3de6070100 eb07 488d3dc5070100 4533ed }
		$sequence_13 = { 51 6a00 6a00 6a1a 6a00 ff15???????? 68???????? }
		$sequence_14 = { 51 8d94247c040000 52 ff15???????? }
		$sequence_15 = { 8b4508 ff34c580b10010 ff15???????? 5d c3 6a0c }

	condition:
		7 of them and filesize <266240
}
