#matasano 5.38
 
import random
import binascii
import os
from matasano10 import aes_cbc_decrypt, aes_cbc_encrypt
from matasano28 import sha1
from matasano18 import bi2ba
from matasano34 import netsim
from matasano36 import sfs2int
from hashlib import sha256
import hmac
import sys

#Pre-agreed constants defined as global
g = 2
pstr = """
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff
"""
p = long(eval('0x'+''.join(pstr.split())))
k=3

#Just a random smallish word list (picked up from Electrum)
word_list = [
    "like", "just", "love", "know", "never", "want", "time", "out", "there",
    "make", "look", "eye", "down", "only", "think", "heart", "back", "then",
    "into", "about", "more", "away", "still", "them", "take", "thing", "even",
    "through", "long", "always", "world", "too", "friend", "tell", "try",
    "hand", "thought", "over", "here", "other", "need", "smile", "again",
    "much", "cry", "been", "night", "ever", "little", "said", "end", "some",
    "those", "around", "mind", "people", "girl", "leave", "dream", "left",
    "turn", "myself", "give", "nothing", "really", "off", "before", "something",
    "find", "walk", "wish", "good", "once", "place", "ask", "stop", "keep",
    "watch", "seem", "everything", "wait", "got", "yet", "made", "remember",
    "start", "alone", "run", "hope", "maybe", "believe", "body", "hate",
    "after", "close", "talk", "stand", "own", "each", "hurt", "help", "home",
    "god", "soul", "new", "many", "two", "inside", "should", "true", "first",
    "fear", "mean", "better", "play", "another", "gone", "change", "use",
    "wonder", "someone", "hair", "cold", "open", "best", "any", "behind",
    "happen", "water", "dark", "laugh", "stay", "forever", "name", "work",
    "show", "sky", "break", "came", "deep", "door", "put", "black", "together",
    "upon", "happy", "such", "great", "white", "matter", "fill", "past",
    "please", "burn", "cause", "enough", "touch", "moment", "soon", "voice",
    "scream", "anything", "stare", "sound", "red", "everyone", "hide", "kiss",
    "truth", "death", "beautiful", "mine", "blood", "broken", "very", "pass",
    "next", "forget", "tree", "wrong", "air", "mother", "understand", "lip",
    "hit", "wall", "memory", "sleep", "free", "high", "realize", "school",
    "might", "skin", "sweet", "perfect", "blue", "kill", "breath", "dance",
    "against", "fly", "between", "grow", "strong", "under", "listen", "bring",
    "sometimes", "speak", "pull", "person", "become", "family", "begin",
    "ground", "real", "small", "father", "sure", "feet", "rest", "young",
    "finally", "land", "across", "today", "different", "guy", "line", "fire",
    "reason", "reach", "second", "slowly", "write", "eat", "smell", "mouth",
    "step", "learn", "three", "floor", "promise", "breathe", "darkness", "push",
    "earth", "guess", "save", "song", "above", "along", "both", "color",
    "house", "almost", "sorry", "anymore", "brother", "okay", "dear", "game",
    "fade", "already", "apart", "warm", "beauty", "heard", "notice", "question",
    "shine", "began", "piece", "whole", "shadow", "secret", "street", "within",
    "finger", "point", "morning", "whisper", "child", "moon", "green", "story",
    "glass", "kid", "silence", "since", "soft", "yourself", "empty", "shall",
    "angel", "answer", "baby", "bright", "dad", "path", "worry", "hour", "drop",
    "follow", "power", "war", "half", "flow", "heaven", "act", "chance", "fact",
    "least", "tired", "children", "near", "quite", "afraid", "rise", "sea",
    "taste", "window", "cover", "nice", "trust", "lot", "sad", "cool", "force",
    "peace", "return", "blind", "easy", "ready", "roll", "rose", "drive",
    "held", "music", "beneath", "hang", "mom", "paint", "emotion", "quiet",
    "clear", "cloud", "few", "pretty", "bird", "outside", "paper", "picture",
    "front", "rock", "simple", "anyone", "meant", "reality", "road", "sense",
    "waste", "bit", "leaf", "thank", "happiness", "meet", "men", "smoke",
    "truly", "decide", "self", "age", "book", "form", "alive", "carry",
    "escape", "damn", "instead", "able", "ice", "minute", "throw", "catch",
    "leg", "ring", "course", "goodbye", "lead", "poem", "sick", "corner",
    "desire", "known", "problem", "remind", "shoulder", "suppose", "toward",
    "wave", "drink", "jump", "woman", "pretend", "sister", "week", "human",
    "joy", "crack", "grey", "pray", "surprise", "dry", "knee", "less", "search",
    "bleed", "caught", "clean", "embrace", "future", "king", "son", "sorrow",
    "chest", "hug", "remain", "sat", "worth", "blow", "daddy", "final",
    "parent", "tight", "also", "create", "lonely", "safe", "cross", "dress",
    "evil", "silent", "bone", "fate", "perhaps", "anger", "class", "scar",
    "snow", "tiny", "tonight", "continue", "control", "dog", "edge", "mirror",
    "month", "suddenly", "comfort", "given", "loud", "quickly", "gaze", "plan",
    "rush", "stone", "town", "battle", "ignore", "spirit", "stood", "stupid",
    "yours", "brown", "build", "dust", "hey", "kept", "pay", "phone", "twist",
    "although", "ball", "beyond", "hidden", "nose", "taken", "fail", "float",
    "pure", "somehow", "wash", "wrap", "angry", "cheek", "creature",
    "forgotten", "heat", "rip", "single", "space", "special", "weak",
    "whatever", "yell", "anyway", "blame", "job", "choose", "country", "curse",
    "drift", "echo", "figure", "grew", "laughter", "neck", "suffer", "worse",
    "yeah", "disappear", "foot", "forward", "knife", "mess", "somewhere",
    "stomach", "storm", "beg", "idea", "lift", "offer", "breeze", "field",
    "five", "often", "simply", "stuck", "win", "allow", "confuse", "enjoy",
    "except", "flower", "seek", "strength", "calm", "grin", "gun", "heavy",
    "hill", "large", "ocean", "shoe", "sigh", "straight", "summer", "tongue",
    "accept", "crazy", "everyday", "exist", "grass", "mistake", "sent", "shut",
    "surround", "table", "ache", "brain", "destroy", "heal", "nature", "shout",
    "sign", "stain", "choice", "doubt", "glance", "glow", "mountain", "queen",
    "stranger", "throat", "tomorrow", "city", "either", "fish", "flame",
    "rather", "shape", "spin", "spread", "ash", "distance", "finish", "image",
    "imagine", "important", "nobody", "shatter", "warmth", "became", "feed",
    "flesh", "funny", "lust", "shirt", "trouble", "yellow", "attention", "bare",
    "bite", "money", "protect", "amaze", "appear", "born", "choke",
    "completely", "daughter", "fresh", "friendship", "gentle", "probably",
    "six", "deserve", "expect", "grab", "middle", "nightmare", "river",
    "thousand", "weight", "worst", "wound", "barely", "bottle", "cream",
    "regret", "relationship", "stick", "test", "crush", "endless", "fault",
    "itself", "rule", "spill", "art", "circle", "join", "kick", "mask",
    "master", "passion", "quick", "raise", "smooth", "unless", "wander",
    "actually", "broke", "chair", "deal", "favorite", "gift", "note", "number",
    "sweat", "box", "chill", "clothes", "lady", "mark", "park", "poor",
    "sadness", "tie", "animal", "belong", "brush", "consume", "dawn", "forest",
    "innocent", "pen", "pride", "stream", "thick", "clay", "complete", "count",
    "draw", "faith", "press", "silver", "struggle", "surface", "taught",
    "teach", "wet", "bless", "chase", "climb", "enter", "letter", "melt",
    "metal", "movie", "stretch", "swing", "vision", "wife", "beside", "crash",
    "forgot", "guide", "haunt", "joke", "knock", "plant", "pour", "prove",
    "reveal", "steal", "stuff", "trip", "wood", "wrist", "bother", "bottom",
    "crawl", "crowd", "fix", "forgive", "frown", "grace", "loose", "lucky",
    "party", "release", "surely", "survive", "teacher", "gently", "grip",
    "speed", "suicide", "travel", "treat", "vein", "written", "cage", "chain",
    "conversation", "date", "enemy", "however", "interest", "million", "page",
    "pink", "proud", "sway", "themselves", "winter", "church", "cruel", "cup",
    "demon", "experience", "freedom", "pair", "pop", "purpose", "respect",
    "shoot", "softly", "state", "strange", "bar", "birth", "curl", "dirt",
    "excuse", "lord", "lovely", "monster", "order", "pack", "pants", "pool",
    "scene", "seven", "shame", "slide", "ugly", "among", "blade", "blonde",
    "closet", "creek", "deny", "drug", "eternity", "gain", "grade", "handle",
    "key", "linger", "pale", "prepare", "swallow", "swim", "tremble", "wheel",
    "won", "cast", "cigarette", "claim", "college", "direction", "dirty",
    "gather", "ghost", "hundred", "loss", "lung", "orange", "present", "swear",
    "swirl", "twice", "wild", "bitter", "blanket", "doctor", "everywhere",
    "flash", "grown", "knowledge", "numb", "pressure", "radio", "repeat",
    "ruin", "spend", "unknown", "buy", "clock", "devil", "early", "false",
    "fantasy", "pound", "precious", "refuse", "sheet", "teeth", "welcome",
    "add", "ahead", "block", "bury", "caress", "content", "depth", "despite",
    "distant", "marry", "purple", "threw", "whenever", "bomb", "dull", "easily",
    "grasp", "hospital", "innocence", "normal", "receive", "reply", "rhyme",
    "shade", "someday", "sword", "toe", "visit", "asleep", "bought", "center",
    "consider", "flat", "hero", "history", "ink", "insane", "muscle", "mystery",
    "pocket", "reflection", "shove", "silently", "smart", "soldier", "spot",
    "stress", "train", "type", "view", "whether", "bus", "energy", "explain",
    "holy", "hunger", "inch", "magic", "mix", "noise", "nowhere", "prayer",
    "presence", "shock", "snap", "spider", "study", "thunder", "trail", "admit",
    "agree", "bag", "bang", "bound", "butterfly", "cute", "exactly", "explode",
    "familiar", "fold", "further", "pierce", "reflect", "scent", "selfish",
    "sharp", "sink", "spring", "stumble", "universe", "weep", "women",
    "wonderful", "action", "ancient", "attempt", "avoid", "birthday", "branch",
    "chocolate", "core", "depress", "drunk", "especially", "focus", "fruit",
    "honest", "match", "palm", "perfectly", "pillow", "pity", "poison", "roar",
    "shift", "slightly", "thump", "truck", "tune", "twenty", "unable", "wipe",
    "wrote", "coat", "constant", "dinner", "drove", "egg", "eternal", "flight",
    "flood", "frame", "freak", "gasp", "glad", "hollow", "motion", "peer",
    "plastic", "root", "screen", "season", "sting", "strike", "team", "unlike",
    "victim", "volume", "warn", "weird", "attack", "await", "awake", "built",
    "charm", "crave", "despair", "fought", "grant", "grief", "horse", "limit",
    "message", "ripple", "sanity", "scatter", "serve", "split", "string",
    "trick", "annoy", "blur", "boat", "brave", "clearly", "cling", "connect",
    "fist", "forth", "imagination", "iron", "jock", "judge", "lesson", "milk",
    "misery", "nail", "naked", "ourselves", "poet", "possible", "princess",
    "sail", "size", "snake", "society", "stroke", "torture", "toss", "trace",
    "wise", "bloom", "bullet", "cell", "check", "cost", "darling", "during",
    "footstep", "fragile", "hallway", "hardly", "horizon", "invisible",
    "journey", "midnight", "mud", "nod", "pause", "relax", "shiver", "sudden",
    "value", "youth", "abuse", "admire", "blink", "breast", "bruise",
    "constantly", "couple", "creep", "curve", "difference", "dumb", "emptiness",
    "gotta", "honor", "plain", "planet", "recall", "rub", "ship", "slam",
    "soar", "somebody", "tightly", "weather", "adore", "approach", "bond",
    "bread", "burst", "candle", "coffee", "cousin", "crime", "desert",
    "flutter", "frozen", "grand", "heel", "hello", "language", "level",
    "movement", "pleasure", "powerful", "random", "rhythm", "settle", "silly",
    "slap", "sort", "spoken", "steel", "threaten", "tumble", "upset", "aside",
    "awkward", "bee", "blank", "board", "button", "card", "carefully",
    "complain", "crap", "deeply", "discover", "drag", "dread", "effort",
    "entire", "fairy", "giant", "gotten", "greet", "illusion", "jeans", "leap",
    "liquid", "march", "mend", "nervous", "nine", "replace", "rope", "spine",
    "stole", "terror", "accident", "apple", "balance", "boom", "childhood",
    "collect", "demand", "depression", "eventually", "faint", "glare", "goal",
    "group", "honey", "kitchen", "laid", "limb", "machine", "mere", "mold",
    "murder", "nerve", "painful", "poetry", "prince", "rabbit", "shelter",
    "shore", "shower", "soothe", "stair", "steady", "sunlight", "tangle",
    "tease", "treasure", "uncle", "begun", "bliss", "canvas", "cheer", "claw",
    "clutch", "commit", "crimson", "crystal", "delight", "doll", "existence",
    "express", "fog", "football", "gay", "goose", "guard", "hatred",
    "illuminate", "mass", "math", "mourn", "rich", "rough", "skip", "stir",
    "student", "style", "support", "thorn", "tough", "yard", "yearn",
    "yesterday", "advice", "appreciate", "autumn", "bank", "beam", "bowl",
    "capture", "carve", "collapse", "confusion", "creation", "dove", "feather",
    "girlfriend", "glory", "government", "harsh", "hop", "inner", "loser",
    "moonlight", "neighbor", "neither", "peach", "pig", "praise", "screw",
    "shield", "shimmer", "sneak", "stab", "subject", "throughout", "thrown",
    "tower", "twirl", "wow", "army", "arrive", "bathroom", "bump", "cease",
    "cookie", "couch", "courage", "dim", "guilt", "howl", "hum", "husband",
    "insult", "led", "lunch", "mock", "mostly", "natural", "nearly", "needle",
    "nerd", "peaceful", "perfection", "pile", "price", "remove", "roam",
    "sanctuary", "serious", "shiny", "shook", "sob", "stolen", "tap", "vain",
    "void", "warrior", "wrinkle", "affection", "apologize", "blossom", "bounce",
    "bridge", "cheap", "crumble", "decision", "descend", "desperately", "dig",
    "dot", "flip", "frighten", "heartbeat", "huge", "lazy", "lick", "odd",
    "opinion", "process", "puzzle", "quietly", "retreat", "score", "sentence",
    "separate", "situation", "skill", "soak", "square", "stray", "taint",
    "task", "tide", "underneath", "veil", "whistle", "anywhere", "bedroom",
    "bid", "bloody", "burden", "careful", "compare", "concern", "curtain",
    "decay", "defeat", "describe", "double", "dreamer", "driver", "dwell",
    "evening", "flare", "flicker", "grandma", "guitar", "harm", "horrible",
    "hungry", "indeed", "lace", "melody", "monkey", "nation", "object",
    "obviously", "rainbow", "salt", "scratch", "shown", "shy", "stage", "stun",
    "third", "tickle", "useless", "weakness", "worship", "worthless",
    "afternoon", "beard", "boyfriend", "bubble", "busy", "certain", "chin",
    "concrete", "desk", "diamond", "doom", "drawn", "due", "felicity", "freeze",
    "frost", "garden", "glide", "harmony", "hopefully", "hunt", "jealous",
    "lightning", "mama", "mercy", "peel", "physical", "position", "pulse",
    "punch", "quit", "rant", "respond", "salty", "sane", "satisfy", "savior",
    "sheep", "slept", "social", "sport", "tuck", "utter", "valley", "wolf",
    "aim", "alas", "alter", "arrow", "awaken", "beaten", "belief", "brand",
    "ceiling", "cheese", "clue", "confidence", "connection", "daily",
    "disguise", "eager", "erase", "essence", "everytime", "expression", "fan",
    "flag", "flirt", "foul", "fur", "giggle", "glorious", "ignorance", "law",
    "lifeless", "measure", "mighty", "muse", "north", "opposite", "paradise",
    "patience", "patient", "pencil", "petal", "plate", "ponder", "possibly",
    "practice", "slice", "spell", "stock", "strife", "strip", "suffocate",
    "suit", "tender", "tool", "trade", "velvet", "verse", "waist", "witch",
    "aunt", "bench", "bold", "cap", "certainly", "click", "companion",
    "creator", "dart", "delicate", "determine", "dish", "dragon", "drama",
    "drum", "dude", "everybody", "feast", "forehead", "former", "fright",
    "fully", "gas", "hook", "hurl", "invite", "juice", "manage", "moral",
    "possess", "raw", "rebel", "royal", "scale", "scary", "several", "slight",
    "stubborn", "swell", "talent", "tea", "terrible", "thread", "torment",
    "trickle", "usually", "vast", "violence", "weave", "acid", "agony",
    "ashamed", "awe", "belly", "blend", "blush", "character", "cheat", "common",
    "company", "coward", "creak", "danger", "deadly", "defense", "define",
    "depend", "desperate", "destination", "dew", "duck", "dusty", "embarrass",
    "engine", "example", "explore", "foe", "freely", "frustrate", "generation",
    "glove", "guilty", "health", "hurry", "idiot", "impossible", "inhale",
    "jaw",
    "kingdom", "mention", "mist", "moan", "mumble", "mutter", "observe", "ode",
    "pathetic", "pattern", "pie", "prefer", "puff", "rape", "rare", "revenge",
    "rude", "scrape", "spiral", "squeeze", "strain", "sunset", "suspend",
    "sympathy", "thigh", "throne", "total", "unseen", "weapon", "weary"
]


class MaliciousServer(object):
    def reset(self):
        self.A = None
        self.B = None
        self.u = None
        self.b = None
        self.salt = None
        
    def recv_email(self, em, A):
        self.A = A
        self.b = random.randint(1,p-1)
        self.B = pow(g, self.b, p)
        self.u = int(eval('0x'+binascii.hexlify(os.urandom(16))))
        self.salt = random.randint(1, p-1)
        return self.salt, self.B, self.u
    
    def recv_token(self, token):
        #use the token, which is hmac(K, salt)
        #to crack the password
        for w in word_list:
            x = sfs2int(self.salt, w)
            v = pow(g, x, p)
            S = pow( (A * pow(v, self.u, p)), self.b, p)
            K = sha256(bi2ba(S)).digest()
            t = hmac.new(K, bi2ba(self.salt), sha256).hexdigest()
            if t==token:
                print 'cracked, password was: '+w
                return True, 'Thank you!'
        print 'failed to crack password'
        return True, 'damn, OK...'
            
class Server(object):
    def reset(self):
        self.A = None
        self.B = None
        self.u = None
        self.b = None
        #cheat-y cheat: just set the email
        #and the password here; in reality,
        #there would be no need, you can store
        #self.v and self.salt instead (that is
        #to say, make a database of pairs,
        #thus making rainbow table style attacks
        #difficult.)
        self.email = "me@there.com"
        password = "password"        
        self.salt = random.randint(1, p-1)
        x = sfs2int(self.salt, password)
        self.v = pow(g, x, p)
    
    def recv_email(self, em, A):
        if not em==self.email:
            return None, None, None
        self.A = A
        self.b = random.randint(1,p-1)
        self.B = pow(g, self.b, p)
        self.u = int(eval('0x'+binascii.hexlify(os.urandom(16))))       
        return self.salt, self.B, self.u
    
    def recv_token(self, token):
        self.S = pow( (self.A*pow(self.v, self.u, p)) , self.b, p)
        K = sha256(bi2ba(self.S)).digest()
        t = hmac.new(K, bi2ba(self.salt), sha256).hexdigest()
        if t==token:
            return True, 'Access granted.'
        return False, 'Access denied.'
        
def print_usage():
    print """Syntax: python matasano38.py [0/1]
            0 = honest server
            1 = MITM server will crack your password
            """

if __name__ == '__main__':
    '''Big copy-paste of challenge 36, to implement the
    simplified (and flawed version) of the algo.
    '''
    if len(sys.argv) < 2:
        print_usage()
        exit(0)

    if int(sys.argv[1])==0:
        server = Server()
    elif int(sys.argv[1])==1:
        server = MaliciousServer()
    else:
        print_usage()
        exit(0)
    badcount = 0
    while True:
        server.reset()
        em = raw_input('Enter your email: ')
        pwd = raw_input('Enter your password: ')
        #gen ephemeral pubkey for this session:
        a = random.randint(1, p-1)
        A = pow(g, a, p)
        res = server.recv_email(em, A)
        if not res[0] or not res[1]:
            print 'Error, wrong email'
            badcount += 1
            if badcount > 3:
                print 'Go away'
                exit(0)
            continue
        salt = res[0]
        B = res[1]
        u = res[2]
        #compute same x that server computed
        #to test failure case set the salt to zero or something
        x = sfs2int(salt, pwd)
        S = pow(B, a + u*x, p)
        K = sha256(bi2ba(S)).digest()
        token = hmac.new(K, bi2ba(salt), sha256).hexdigest()
        print 'calculated your ephemeral token: '+token
        print 'now requesting access'
        res = server.recv_token(token)
        if not res[0]:
            badcount += 1
            if badcount > 3:
                print 'Go away'
                exit(0)
            print res[1]
        else:
            print res[1]
            exit(0)
        
        