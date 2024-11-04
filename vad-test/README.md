# Voice Activity Detection Model Test

Testing Environment
- Google Colab (Intel Xeon CPUs, 13 GB RAM)
- GitHub Codespace (2 Core vCPU, 8 GB RAM)

Input (WAV Format) : Sample from VoxCeleb Data Sets
- voxceleb/TomCruiseSpeaks_sample1.wav
- voxceleb/TomCruiseSpeaks_sample2.wav
- voxceleb/TomCruiseSpeaks_sampleshort.wav

## Model 1 : PyAnnote (pyannote/voice-activity-detection)

### Output from Sample 1: VoxCeleb/TomCruiseSpeaks_sample1.wav

[ 00:00:00.284 -->  00:00:03.270] A SPEECH

### Output from Sample 2:  VoxCeleb/TomCruiseSpeaks_sample2.wav

[ 00:00:00.233 -->  00:00:03.405] A SPEECH

### Output from Sample 3:  VoxCeleb/TomCruiseSpeaks_sampleshort.wav

[ 00:00:00.030 -->  00:00:01.448] A SPEECH

## Model 2 : Silero (snakers4/silero-vad)

### Output from Sample 1: VoxCeleb/TomCruiseSpeaks_sample1.wav

[{'start': 0.3, 'end': 1.5}, {'start': 2.0, 'end': 3.3}]

### Output from Sample 2:  VoxCeleb/TomCruiseSpeaks_sample2.wav

[{'start': 0.2, 'end': 3.4}]

### Output from Sample 3:  VoxCeleb/TomCruiseSpeaks_sampleshort.wav

[{'start': 0.0, 'end': 1.3}]

## Model 3 : Wave2Vec2

### Output from Sample 1: VoxCeleb/TomCruiseSpeaks_sample1.wav

[{'word': 'AT', 'start_time': 0.34, 'end_time': 0.38}, {'word': 'THE', 'start_time': 0.44, 'end_time': 0.54}, {'word': 'END', 'start_time': 0.62, 'end_time': 0.7}, {'word': 'OF', 'start_time': 0.78, 'end_time': 0.82}, {'word': 'IT', 'start_time': 0.92, 'end_time': 0.98}, {'word': 'YOU', 'start_time': 1.08, 'end_time': 1.2}, {'word': 'YOU', 'start_time': 2.08, 'end_time': 2.16}, {'word': 'WANT', 'start_time': 2.24, 'end_time': 2.38}, {'word': 'TO', 'start_time': 2.4, 'end_time': 2.46}, {'word': 'GO', 'start_time': 2.5, 'end_time': 2.6}, {'word': 'OUT', 'start_time': 2.74, 'end_time': 2.82}, {'word': 'AND', 'start_time': 2.88, 'end_time': 2.94}, {'word': 'YOU', 'start_time': 2.96, 'end_time': 3.04}, {'word': 'WANT', 'start_time': 3.1, 'end_time': 3.2}]

### Output from Sample 2:  VoxCeleb/TomCruiseSpeaks_sample2.wav

[{'word': 'YE', 'start_time': 0.2, 'end_time': 0.3}, {'word': 'I', 'start_time': 0.42, 'end_time': 0.44}, {'word': 'LOVE', 'start_time': 0.54, 'end_time': 0.7}, {'word': 'THESE', 'start_time': 0.74, 'end_time': 0.9}, {'word': 'CEREMONIES', 'start_time': 1.36, 'end_time': 1.84}, {'word': 'IRE', 'start_time': 1.88, 'end_time': 1.96}, {'word': 'MEMBERS', 'start_time': 1.98, 'end_time': 2.24}, {'word': 'A', 'start_time': 2.28, 'end_time': 2.32}, {'word': 'LITTLE', 'start_time': 2.34, 'end_time': 2.52}, {'word': 'KID', 'start_time': 2.56, 'end_time': 2.8}, {'word': 'I', 'start_time': 2.94, 'end_time': 2.96}, {'word': 'USED', 'start_time': 3.06, 'end_time': 3.18}, {'word': 'TO', 'start_time': 3.24, 'end_time': 3.32}]

### Output from Sample 3:  VoxCeleb/TomCruiseSpeaks_sampleshort.wav

[{'word': 'ONE', 'start_time': 0.06, 'end_time': 0.14}, {'word': 'TO', 'start_time': 0.16, 'end_time': 0.22}, {'word': 'EMBRACE', 'start_time': 0.3, 'end_time': 0.62}, {'word': 'LIFE', 'start_time': 0.74, 'end_time': 0.98}]

## Model 4 : Whisper Tiny

### Output from Sample 1: VoxCeleb/TomCruiseSpeaks_sample1.wav

[{'id': 0, 'seek': 0, 'start': 0.0, 'end': 3.3200000000000003, 'text': ' At the end of it you you want to go out and you want to', 'tokens': [50364, 1711, 264, 917, 295, 309, 291, 291, 528, 281, 352, 484, 293, 291, 528, 281, 50530], 'temperature': 0.0, 'avg_logprob': -0.31429534488254124, 'compression_ratio': 1.1458333333333333, 'no_speech_prob': 0.2468426525592804}]

### Output from Sample 2:  VoxCeleb/TomCruiseSpeaks_sample2.wav

[{'id': 0, 'seek': 0, 'start': 0.0, 'end': 3.36, 'text': " You know, I love these ceremonies. I remember there's a little kid I used to", 'tokens': [50364, 509, 458, 11, 286, 959, 613, 36176, 13, 286, 1604, 456, 311, 257, 707, 1636, 286, 1143, 281, 50532], 'temperature': 0.0, 'avg_logprob': -0.39154079982212614, 'compression_ratio': 1.0133333333333334, 'no_speech_prob': 0.037378426641225815}]

### Output from Sample 3:  VoxCeleb/TomCruiseSpeaks_sampleshort.wav

[{'id': 0, 'seek': 0, 'start': 0.0, 'end': 2.0, 'text': ' want to embrace life.', 'tokens': [50364, 528, 281, 14038, 993, 13, 50464], 'temperature': 0.0, 'avg_logprob': -0.7155290246009827, 'compression_ratio': 0.7241379310344828, 'no_speech_prob': 0.037492312490940094}]

## Model 5 : WebRTC

### Output

Doesn't work in our samples since The WebRTC VAD only accepts 16-bit mono PCM audio, sampled at 8000, 16000, 32000 or 48000 Hz. A frame must be either 10, 20, or 30 ms in duration.

# EZKL Integration Test

## Model 1 : Wav2Vec2

### Runtime Error

```
ezkl.gen_settings(self.model_path, self.settings_path)
```
Failed to generate settings: 
[graph] [tract] Undetermined symbol in expression: sequence_length

## Model 1 : Wav2Vec2

### Runtime Error

```
ezkl.gen_settings(self.model_path, self.settings_path)
```
Failed to generate settings: 
[graph] [tract] Undetermined symbol in expression: sequence_length

## Model 2 : Whipser Tiny

### Kernel Error 

The Kernel crashed while executing code in the current cell or a previous cell. 
From the investigate in EZKL discord and github, transformer model require a lot of memory (~700GB)

## Model 3 : Silero

### RuntimeError

Failed to load model