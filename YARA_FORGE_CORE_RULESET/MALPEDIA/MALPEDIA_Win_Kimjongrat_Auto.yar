rule MALPEDIA_Win_Kimjongrat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "db4baf64-c410-5dd4-86f2-fb3657762c91"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kimjongrat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.kimjongrat_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "515b099b5f4271a4a56e7e428e24670deb74340ff8bb9a2bab6a20ed3f485ca9"
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
		$sequence_0 = { e9???????? c6840db4edffff2a e9???????? c6840db4edffff26 e9???????? c6840db4edffff5b eb6c }
		$sequence_1 = { e8???????? 8bd8 83c414 85db 0f8508010000 33c9 894de4 }
		$sequence_2 = { ff7004 8d4108 50 e8???????? 8b5508 8b4840 894a20 }
		$sequence_3 = { ff7508 e8???????? 6a01 57 6a4c 56 e8???????? }
		$sequence_4 = { e9???????? 8b4c8f58 894dd0 898d60ffffff 8b55a4 b860240000 66854208 }
		$sequence_5 = { c68540d0ffff00 e8???????? 83c40c ba???????? 33c9 8a02 42 }
		$sequence_6 = { e9???????? c6840da0e8ffff77 e9???????? c6840da0e8ffff76 e9???????? c6840da0e8ffff65 e9???????? }
		$sequence_7 = { ff30 e8???????? 8b450c 83c404 c70000000000 8b55f8 c645f000 }
		$sequence_8 = { e9???????? c6840dccf3ffff2d e9???????? c6840dccf3ffff7d e9???????? c6840dccf3ffff29 e9???????? }
		$sequence_9 = { 8bf8 83c404 897dac 85ff 0f8418f3ffff b800400000 66854608 }

	condition:
		7 of them and filesize <1572864
}
