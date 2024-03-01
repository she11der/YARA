rule MALPEDIA_Win_Winmm_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e5922e79-076b-5a5c-ba27-8c0bb532ca1f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.winmm"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.winmm_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "9d8038e46a83e5b1250014db0840b8d665afb5078d6d9005cce493b4024246af"
		score = 60
		quality = 35
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
		$sequence_0 = { 740c 663d3000 7406 663d2000 750b 668b042e 03f5 }
		$sequence_1 = { 03ce 7504 33c0 5e }
		$sequence_2 = { 7d03 6a01 5f 85ff 0f8449ffffff }
		$sequence_3 = { 89462c ff15???????? 8bce 894604 e8???????? 85c0 }
		$sequence_4 = { 8bc8 ff5274 c3 33c0 c3 c3 56 }
		$sequence_5 = { 83c308 bf80000000 eb1d 83e86e }
		$sequence_6 = { e8???????? 59 eb1d 6a02 83c304 5f }
		$sequence_7 = { 663d2000 750b 668b042e 03f5 663bc7 75c0 397c2428 }
		$sequence_8 = { 7c02 8bfd 3b7c2428 7f5a 8b7c2428 }
		$sequence_9 = { 83c40c 85c0 752d 83c606 }

	condition:
		7 of them and filesize <278528
}