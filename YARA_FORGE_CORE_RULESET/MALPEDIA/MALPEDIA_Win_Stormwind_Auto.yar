rule MALPEDIA_Win_Stormwind_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "134843ba-afb3-5108-9e28-7ec5026e872c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stormwind"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.stormwind_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "81578edc87d2c38ca6c94ce63cf22ed064b72d5bc6a7c525985af57574ba5c73"
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
		$sequence_0 = { e8???????? 83c404 8bf7 3b3b 75e2 }
		$sequence_1 = { 83e4f8 81ec1c010000 53 8b5d10 56 57 8b7d0c }
		$sequence_2 = { e8???????? 83ec0c c745fc00000000 8d4e04 e8???????? 85c0 8b06 }
		$sequence_3 = { 50 ff7604 56 e8???????? 894604 c745d801000000 8b4804 }
		$sequence_4 = { 59 8b7d08 33db 391cfd88e40410 755c 6a18 e8???????? }
		$sequence_5 = { 83fa05 7509 8b852cfdffff 89470c 6bc20c 57 ff90c04e0410 }
		$sequence_6 = { 8d4de4 e8???????? 68???????? 8d45e4 c745e4740c0410 50 e8???????? }
		$sequence_7 = { f7fe 57 8bc2 99 }
		$sequence_8 = { c74508???????? 50 8d4de4 e8???????? 68???????? 8d45e4 c745e4740c0410 }
		$sequence_9 = { 8975d4 68b8020000 c645fc01 e8???????? }

	condition:
		7 of them and filesize <741376
}
