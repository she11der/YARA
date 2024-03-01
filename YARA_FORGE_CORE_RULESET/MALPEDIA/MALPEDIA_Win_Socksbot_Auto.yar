rule MALPEDIA_Win_Socksbot_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "9bcf8cfe-6674-56a4-ae23-27a14bd76431"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.socksbot"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.socksbot_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "751966a23ad60ac8819a9938a949afcb7d6a09a99a37898a0110d849f807b7bf"
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
		$sequence_0 = { 6a50 ff7508 33f6 8975fc e8???????? 8bd8 59 }
		$sequence_1 = { 59 e9???????? 55 8bec ff4d0c 7509 ff7508 }
		$sequence_2 = { 46 8a1c39 41 3b4d0c 7cce 5f 8935???????? }
		$sequence_3 = { 6a00 ff7508 6a03 e8???????? 83c410 ff7704 }
		$sequence_4 = { 48 741b 48 7536 53 }
		$sequence_5 = { e8???????? 8bd8 8b45fc 8945f0 83c008 }
		$sequence_6 = { 8b75fc 53 ff15???????? 57 e8???????? }
		$sequence_7 = { 75ed ff7508 6bc94c 8b5dfc 03cf 51 53 }
		$sequence_8 = { 8a0c37 880e 4a 75f7 }
		$sequence_9 = { 81c60c000100 4b 75d2 68???????? ff15???????? a0???????? }

	condition:
		7 of them and filesize <73728
}
