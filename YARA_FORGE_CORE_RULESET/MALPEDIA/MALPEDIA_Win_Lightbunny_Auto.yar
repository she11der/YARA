rule MALPEDIA_Win_Lightbunny_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "546c8a57-6f91-59bb-b683-389534c380bb"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lightbunny"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.lightbunny_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "4c0608cdc020e5347f646e557ecb414bd8f3027b0aca947da82d4930945e8be1"
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
		$sequence_0 = { 6bc930 8b048520ae4100 0fb6440828 83e040 5d }
		$sequence_1 = { 8bc1 83e13f c1f806 6bc930 8b048520ae4100 f644082801 }
		$sequence_2 = { 83c404 6a02 ff35???????? ffd3 }
		$sequence_3 = { 894708 0fb74602 50 ff15???????? }
		$sequence_4 = { ff35???????? ff15???????? c705????????00000000 8b4dfc }
		$sequence_5 = { 51 ff15???????? 85c0 740e 8b400c 8b00 }
		$sequence_6 = { 8d3c9d58ab4100 f00fb10f 8bc8 85c9 740b }
		$sequence_7 = { 83c404 83f801 0f851dffffff 8b5710 33c9 b8???????? 90 }
		$sequence_8 = { 6bc030 c1f906 03048d20ae4100 eb02 8bc6 80782900 7522 }
		$sequence_9 = { 8b75f8 33ff 8b0d???????? 8bc6 8945e4 894de8 }

	condition:
		7 of them and filesize <2376704
}