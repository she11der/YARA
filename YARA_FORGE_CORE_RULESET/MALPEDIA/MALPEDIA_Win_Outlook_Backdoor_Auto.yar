rule MALPEDIA_Win_Outlook_Backdoor_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "10b67e6b-fced-54a6-8f30-b2a0d20f49ea"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.outlook_backdoor"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.outlook_backdoor_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "373fe304abbc2faa8be0b7ba3a307d5b5d4cb0051b5dde767cca54332adde2f8"
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
		$sequence_0 = { ff753c 53 68e9fd0000 ffd6 8d4d00 894568 e8???????? }
		$sequence_1 = { ff10 8b4c2408 ff74240c 8d04c8 8b4804 85c9 740b }
		$sequence_2 = { c9 c20800 56 8bf7 e8???????? 8d771c e8???????? }
		$sequence_3 = { c745e01f000130 895d0c ff15???????? 8b450c 8945f0 895dfc 33c9 }
		$sequence_4 = { 6898000000 e8???????? 59 8945ec c645fc01 }
		$sequence_5 = { f6455404 740e 836554fb 57 56 8d4dbc e8???????? }
		$sequence_6 = { c3 57 6a2c e8???????? 8bf8 59 85ff }
		$sequence_7 = { 5f 5e 8d4302 5b c3 53 8bd9 }
		$sequence_8 = { 50 e8???????? 834d1004 f6451002 740f 836510fd }
		$sequence_9 = { e8???????? 83ec38 56 57 8bf1 8b4604 33ff }

	condition:
		7 of them and filesize <2912256
}
