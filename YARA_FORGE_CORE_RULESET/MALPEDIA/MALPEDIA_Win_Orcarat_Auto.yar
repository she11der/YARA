rule MALPEDIA_Win_Orcarat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "2de223cb-857a-5d4b-8d3a-323fa4ad4ded"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.orcarat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.orcarat_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "12ec16d312c505ceab125190551fe03bd174598263e03e7c0fe4b3239bc4fe94"
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
		$sequence_0 = { f2ae 8d84242c110000 f7d1 50 894c2414 51 }
		$sequence_1 = { 8d8c2418010000 50 51 8d842430110000 52 50 }
		$sequence_2 = { 56 6a00 8d5708 6a10 }
		$sequence_3 = { 53 8dbef4020000 51 50 }
		$sequence_4 = { 8bf0 85f6 7451 8b442414 85c0 7421 }
		$sequence_5 = { f2ae 8d442420 f7d1 50 894c2418 ff15???????? 50 }
		$sequence_6 = { 303d???????? 40 00803d400023 d18a0688078a 46 018847018a46 }
		$sequence_7 = { 5d 5b 81c418020000 c20400 6a01 8d142e }
		$sequence_8 = { ff15???????? 85c0 0f849e010000 8b0f 53 6a01 51 }
		$sequence_9 = { 33db 837d0000 762f 8d542410 c744241000000000 52 6800080000 }

	condition:
		7 of them and filesize <114688
}
