rule MALPEDIA_Win_Webc2_Table_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "398ecdfa-bd77-5001-b308-7e740d6a25e6"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_table"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.webc2_table_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "659cc34946aa5d8ea6957b273afd39f56e48147569d9730da4a86aafe181a1ab"
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
		$sequence_0 = { 8d85e4feffff 50 ff75fc ff15???????? 85c0 0f8461010000 }
		$sequence_1 = { 83c410 881d???????? 8345fc04 ff4dec 0f8567feffff }
		$sequence_2 = { 8dbda1fcffff 889da0fcffff f3ab 66ab aa 8d859cfbffff 6804010000 }
		$sequence_3 = { 53 894dec ffd6 59 }
		$sequence_4 = { 8b45f4 bf???????? 57 50 885c30f4 8b35???????? }
		$sequence_5 = { 50 53 ff15???????? 85c0 750a ff15???????? 32c0 }
		$sequence_6 = { ff75fc 8d85bcfdffff 50 e8???????? 59 }
		$sequence_7 = { 50 8945e8 e8???????? 83c40c 895df8 8d45c4 }
		$sequence_8 = { e8???????? 0fb745e0 50 0fb745de 50 }
		$sequence_9 = { ff7508 6a01 50 ff15???????? 56 }

	condition:
		7 of them and filesize <49152
}
