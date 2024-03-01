rule MALPEDIA_Win_Manjusaka_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "9f188d62-91cb-5093-86fd-1c78b358599b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.manjusaka"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.manjusaka_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "dab9ae475e0b441f3d26af80a0ebc722e21c766bc33599d09d1c1a5353ad7516"
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
		$sequence_0 = { ebb8 488d05b77a1000 4889442450 48c744245801000000 48c744246000000000 488d05f9b01100 4889442470 }
		$sequence_1 = { 4c89bc2480040000 4c8939 4c897108 48895910 48c7411800800000 0f117018 48897930 }
		$sequence_2 = { 791d 418b4128 41034124 4863c8 488bc2 48f7d8 48c1e00a }
		$sequence_3 = { 89411c 488b45d7 2b4527 05feffff07 89710c 894120 8b45db }
		$sequence_4 = { 4989f8 e8???????? 48ffcb 75ed 0f57f6 488d9c2410010000 0f297320 }
		$sequence_5 = { 898c24f8000000 48896c2448 3b08 0f8c21fdffff 4c8bbc24f0000000 4d85f6 7424 }
		$sequence_6 = { 814d4002020000 4533c0 48894500 498bcd 83c8ff 66894544 b8c8000000 }
		$sequence_7 = { 89573c 48894740 895750 488b442e60 48894758 488b442e28 488b4860 }
		$sequence_8 = { f7d8 894c2420 448bc5 498bcd 1bd2 4533c9 83e2fc }
		$sequence_9 = { e8???????? 4889d9 e8???????? 488d4f70 e8???????? 488d8fe0000000 e8???????? }

	condition:
		7 of them and filesize <4772864
}