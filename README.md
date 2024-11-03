# voizk-ML

This hack failed several times and basically it's impossible with current tech to achieve the original goal and now it's time to explain why exactly. I'll start with describing how those goals were set, which research routes we followed, and then continue what limitations exactly we hit.

# Overall vision

While it's hard to hack a properly secure biometric auth system from scratch that part specifically didn't concern us much, what we wanted to actually explore was whether the ZK tech allows us to actually build it in a decentralized / trustless / verified way (on the assumption that actually cool parts are somehow made to work)

The cool part we never actually expected to work are ML model that can be quickly enough trained and used for inference during authentication. In a real system that part would require a lot of design work and testing, so we originally set the goal to just try and test already available examples of voice-related tools (both ML and OG) and see if they can be run in ZK runtimes like ZKML and ZKVM frameworks in any way that would give us proof of end-to-end-verification (like, as long as we can process the data is some way and generate a proof we can reasonably change the actual processing to suit future needs). So the core of our research was finding the right tech and see if it can run with those frameworks.

And our main conclusion is a soft-negative, we cannot do this with the current state of ZK tech. The most common answer I hear on many questions to the tune of "can we use ZK to verify this complex thing?". It's not impossible in theory, just in practice right now.

# First plan

Was including four principal components plus a couple side cars: 1) pre-processing of the raw data with feature extraction 2-3) two ML models to actually consume the pre-processed data and provide meaningful prediction 4) post-processing with additional checks giving the final answer yes/no - is the user authenticated?

Turns out ZKVMs are still too limited, we cannot process a large input there, most libraries cannot be compiled, essentially the only thing we can run from the world of Rust is simple processing of short enough input strings + plus simple computations (it can hash, it can verify proofs, it can operate on strings and numbers to some extent... processig sound data for cleaning and extraction... well, it's not completely impossible, there are libraries and algorithms, it's just hard to implement from scratch and overhead would be huge even then)

LSTM or RNN model that can consume such cleaned and condensed input can work but requires training on a large enough data set (not as good for a few-shots prediction on just a couple samples users typically provide for authentication purposes) and we cannot use pre-trained models good with few-shots prediction within ZKML frameworks like ezkl.

But the first point is bad enough: if we cannot verify pre-processing we already cannot provide anything end-to-end verified. A wall is here, very close.

# Second plan

After that we tried to find ML tools to process raw sound, there are networks trained on VoxCeleb dataset which could be used in our fun example, also some speech-to-text models. We tried several of them just to see how inference works and what outputs will be there and the wall we hit was also close: ezkl and underlying tract doesn't suport tensor sequence operations and none of those models dealing with sound can be circuitized. The search for a weird workaround gave us nothing good.

It's not impossible to hack something from scratch provided time and resources but it was not our plan and is not our situation. The unfortumate answer is the tech is not ready to manage complex things and we should change the idea to something so simple it doesn't have to process any raw data and only deals with nice discrete series and ideally avoid computationally or otherwise complex operations. I thought about just showing a two-liner in rust concatenating two strings and explaining that it's about the limit of what the tech can run and finish proof generation this week but I don't try to be critical. We just need to develop better core tech here.

This writeup should be extended with actual examples of what we did and charts of the successful parts of research (I mean we did manage to extract spectrograms and MFCCs from raw sound in python code using a library, we just cannot do the same in ZKVM easily) and failure logs (mostly it's ezkl settings generator failing over sequence operations, over and over on every model we tried, but that is our main research result here: typical software or ML engineering approach fails with ZK tooling, anything needs to be super-simplified and often rebuilt from scratch)
