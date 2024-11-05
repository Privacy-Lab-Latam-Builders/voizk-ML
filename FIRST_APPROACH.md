# VoizK R&D

This is the first attempt to write it all down.

There are two distinct components here: voice pre-processing machine (voice laundry Black Box) that uses ML and analytical tools to extract features from the voice sample and features time machine (comparison Blue Box):

1. First step is Voice Laundry Machine - upon receiving a voice sample from the user some tool clips it, washes the background noise away and otherwise prepares the sample for classification. Note is taken on the background noise and such for further analysis (to determine whether the sample was natural or generated), the cleaned sample is timestamped using voice activity recognition and Mel frequencies and potentially other things are extracted in short condensed form (audio becomes a short timeseries with many features, ZKVM is used to verify code execution)
2. Second step is Comparison Time Machine - a small ML model is trained on one speaker’s voice and inference is used to verify new samples as they come in. Weights are kept private (as private as password hashes) but commitment to the weights are used as a sort-of public key (ZKML powered by ezkl is used to verify inference)
3. Third half-step is post-processing of inference results (inference results, degree of variation, and potentially external things are combined to finally authenticate the user), verifies proofs and evaluates early steps execution results to come to a conclusion and provide results for integrations in consumable format.

As with any biometric-based public key security system some centralization at the point of assigning public keys is challenging to overcome. We are exploring ideas.

R&D is what we are currently focusing on, our first epic, both overall project architecture and how specific parts connect, our first tasks are about connecting the first steps in the pipeline: sound preprocessing (aka Voice Laundry) and classifier model. Then we’ll move to data scientific analysis of outputs from the classifier and will have some ideas of how we could use it for definitive speaker recognition and what model we should use and how we should train it for the step three (comparison model) and what the exact outputs of that could look like. Based on that step four should be almost obvious if we have clear enough picture overall providing the outputs our system eventually needs (the step 3 will be just analysing and converting outputs from the previous steps (+ verifying proofs) to the final output format we need).

Next epic would be rough implementation of the overall system that works somehow, followed by securing the things so that proofs of all parts are correctly evaluated and verified in the final step. Then bonus steps would be thinking about alternative solutions for verified computation steps and privacy schemes for per-user training data. Samples used for authentication (pre classification) should also be secured in some ways before this can reach any kind of production readiness. But we’re likely to skip all the bonuses to focus on ZK-ML and ZK-VM verification this time round (but if some volunteer provides a way to, say, run some part on MPC-VM more efficiently or securely than our current setup we can be inclusive, I’m open to ideas).

## Voice Laundry Research

Questions:

What tools are there? Anything easy to hack for the right cutting/cleaning parameters?

Are they simple enough and portable enough to compile to MIPS and run in zkMIPS? (what are practical limitations there?)

Will any of the tools provide any info on the background noise and other removed parts that we can analyse?

Can we use nn_filter or other decomposition on spectrogram to condense the output? (I think the right length of output for our sample should be around 20-50)

## Voice Model Research

Questions:

- What classic and novel models are there?
    
    PyAnnote, 
    
- What format of samples they need?
    
    [test.wav](VoizK%20R&D%20129550e91964809daf69ebcde7034358/test.wav)
    
    wav, etc
    
- What outputs they typically provide?
    
    [test.rttm](VoizK%20R&D%20129550e91964809daf69ebcde7034358/test.rttm)
    
    rttm
    
- How diverse are the models with the previous questions?
    
    
- Is there a clear SOTA model or fresh enough good enough one? Anything we can just decide to use because everyone uses it?
- What about [**ReDimNet](https://github.com/IDRnD/ReDimNet), is it any good?**
- How well can any of the models can be circuitized with ezkl?
- What best models that can be circuitized can we shortlist?
- Can a simple enough ML model provide us a short list of timestamps from a sample that can be fed to analysis tools for generating as condensed output as possible (ideally almost constant length for a similar sample)
    
    answer is soft negative, probably no right model exists
    We can use VAD for smart trimming though
    

Voice recognition model should be use to quickly double-check that the right word was spoken

## Architecture Research

Questions:

How well are the two or three parts and their connections defined?

What is the current best understanding diagram of the overall system?

What are the exact outputs and inputs of the whole system?

What are the exact outputs and inputs of each component?

How sustainable it is under heavy user usage?

Is our approach AI proof? i.e. can it distinguish real voice inputs from syntethic voice generated recordings

## Comparison Model Research

Questions:

Can we use any of the existing models (like Linear with normalization) to just predict us a “trust value” or something?

If we cannot and have to use a custom network how can we structure it? (Univariate vs multi-variate prediction or even weirder approaches, we might just use a custom vector operation to check that some value is between the range bounds we found ok during experimentation)

What data science says about our classification outputs?

Can we just use MSE as a soft derivative of changes in the features to be our label/predicted value in the final model?

## Implementation plan

Rough high-level steps

1. Research available tech for each component, figure out what outputs each component has
2. Research available verification tech for each piece of tech, and commitment/proof formats they use
3. Research a way to provide a compact proof as a final result
4. Develop all parts and connections (set up tools, write code, set up pretrained models and training pipelines), in a diffusion fashion: rough shape of a PoC first, then details clarified with every iteration

Questions:

How quickly can we produce a PoC that at least can train and inference the second ML model?