rule MALPEDIA_Win_Slub_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "195b7942-1783-5df2-bcee-76020ab94f8f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.slub"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.slub_auto.yar#L1-L133"
		license_url = "N/A"
		logic_hash = "654a15994e2d79fd54a129ac2f9c4ef4cc1a02067acc10e29921ff8e80b39dab"
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
		$sequence_0 = { ff742420 55 e8???????? 83c414 89442414 85c0 0f8512010000 }
		$sequence_1 = { 807c241200 7407 c686e808000000 80beb406000000 740f ffb6b0060000 ff15???????? }
		$sequence_2 = { c785bcf8ffffcce48f00 8bc8 c785c0f8ffffa0358400 c785c4f8ffff90e98500 e8???????? 8d95bcf8ffff c785bcf8ffffd8e48f00 }
		$sequence_3 = { 85ff 750e 837d2c10 8d4518 0f43c2 3a08 7c13 }
		$sequence_4 = { 85c0 0f8443ffffff 8b96f4000000 85d2 0f8435ffffff 8b8df0000000 6690 }
		$sequence_5 = { 6800000100 6a00 6801000100 56 ff15???????? 89442414 85c0 }
		$sequence_6 = { 898640010000 85c0 0f8416050000 57 e8???????? 83c404 85c0 }
		$sequence_7 = { e8???????? 50 68???????? ffb50cfdffff e8???????? ffb50cfdffff }
		$sequence_8 = { 8d8dc8ebffff 50 ffb5c8ebffff e8???????? 8b85c4ebffff c785dcebffff0f000000 c785d8ebffff00000000 }
		$sequence_9 = { 8b86dc050000 89863c040000 8b86e0050000 898694040000 8b86e4050000 898640040000 8b86e8050000 }

	condition:
		7 of them and filesize <1785856
}
