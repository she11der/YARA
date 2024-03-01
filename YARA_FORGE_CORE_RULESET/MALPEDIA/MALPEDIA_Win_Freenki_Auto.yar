rule MALPEDIA_Win_Freenki_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "96c9c22a-8c0f-508a-9c8b-2adc585b1381"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.freenki"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.freenki_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "ea73b0cd02f4881d245e91a02d5574d630e230bb3618aadd7337accb2e33b167"
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
		$sequence_0 = { 83e03f 6bc830 8b049578394200 c644082801 897de4 c745fcfeffffff }
		$sequence_1 = { 57 e8???????? 83c404 ff75f8 e8???????? 8bf8 }
		$sequence_2 = { f7d9 0bc8 51 53 e8???????? ffb504e7ffff 8bd8 }
		$sequence_3 = { 68???????? 50 ff5110 8b55b8 8b4dcc 2bd1 0f1f440000 }
		$sequence_4 = { 6bd830 8b04bd78394200 f644032801 7444 837c0318ff 743d e8???????? }
		$sequence_5 = { e8???????? 8b3d???????? 33db 0f1f8000000000 8d853cd4ffff 50 }
		$sequence_6 = { 64a300000000 8bf1 89b5e4edffff 33c0 c785c0edffff00000000 }
		$sequence_7 = { 6bce4c 53 0f100419 0f1100 e8???????? 8b4dfc 83c404 }
		$sequence_8 = { 68???????? ffb5e0f9ffff ff15???????? f7d8 5e }
		$sequence_9 = { dd00 ebc6 c745e0b8de4100 e9???????? c745e0c0de4100 e9???????? }

	condition:
		7 of them and filesize <327680
}
