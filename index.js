import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";
import cors from "cors";
import "dotenv/config";
const app = express();
// credentials: true lets the logged-in browser send its better-auth session
// cookie along with cross-origin fetches from the configured frontend URL.
// origin: true echoes the requesting origin back (required by browsers when
// credentials are allowed).
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
const PORT = 5000;

const client = new MongoClient(process.env.MONGODB_URI);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}
const mongoClient = await connectToMongoDB();
const db = mongoClient.db("booklibrary");
const booksCollection = db.collection("books");

// Every borrow record lives here: who borrowed, which book, when, returned?
const borrowsCollection = db.collection("borrows");

// Better Auth users live in the same booklibrary database and are resolved
// from the subject of a verified JWT (see getAuthedUser).
const userCollection = db.collection("user");

// The Next.js app signs JWTs with the Better Auth JWT plugin and publishes
// ONLY the public signing keys here. The backend never shares a secret —
// every claimed identity must verify against this key set.
const authUrl = process.env.BETTER_AUTH_URL;
const backendUrl = process.env.BACKEND_URL;
const jwks = createRemoteJWKSet(new URL("/api/auth/jwks", authUrl));

// Values must stay in sync with the jwt() plugin options in the frontend's
// src/lib/auth.ts.
async function verifyAuthToken(token) {
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: authUrl,
      audience: backendUrl,
      algorithms: ["EdDSA"],
    });
    return payload;
  } catch (error) {
    console.error("JWT verify failed:", error?.name, "-", error?.message);
    return null;
  }
}

// Borrow-system indexes, created once on startup (harmless if they already
// exist and no rows are touched). The second one is the database-level
// guard for "one active borrow per user per book": it is unique ONLY while
// a record is still "borrowed", so even two requests that slip past the
// findOne check at the same moment cannot both insert an active record.
// Returned records are not restricted — the same user may borrow the same
// book again.
try {
  await borrowsCollection.createIndex({ userId: 1, borrowedAt: -1 });
  await borrowsCollection.createIndex(
    { bookId: 1, userId: 1 },
    {
      unique: true,
      partialFilterExpression: { status: "borrowed" },
    }
  );
} catch (err) {
  // If old data already contains duplicate active borrows the unique index
  // cannot be built — keep the server running without it.
  console.error("Borrow indexes warning:", err.message ?? err);
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Resolves the signed-in user only from a verified Better Auth JWT.
 * Nothing sent in a cookie, URL, or request body is trusted for identity.
 */
async function getAuthedUser(req) {
  try {
    const bearerToken =
      String(req.headers.authorization ?? "").match(/^Bearer (.+)$/i)?.[1];

    if (!bearerToken) return null;
    const payload = await verifyAuthToken(bearerToken);
    if (!payload?.sub) return null;
    return userCollection.findOne({ _id: authIdFilter(payload.sub) });
  } catch (error) {
    console.error("Auth user error:", error);
    return null;
  }
}

/**
 * _id filter matching BOTH id shapes the Better Auth mongo adapter produced:
 * newer rows store users/sessions with ObjectId _id / userId references,
 * older rows store plain strings. JWT "sub" claims only ever carry the hex
 * string, so both shapes have to be matchable.
 */
function authIdFilter(id) {
  const idString = String(id ?? "");
  try {
    // $in covers both storage shapes: plain-string rows (older data) and
    // ObjectId rows (what the adapter writes today).
    return { $in: [idString, new ObjectId(idString)] };
  } catch {
    // Not 24-hex — the string form is the only possible shape anyway.
    return idString;
  }
}

/**
 * True when this signed-in user may change the book. Newer books carry
 * ownerUserId (stamped at add time from the session); older books are
 * matched by their ownerEmail instead. String comparison bridges the
 * id-shape differences described on authIdFilter.
 */
function ownsBook(book, user) {
  return (
    String(book.ownerUserId ?? "") === String(user._id ?? "") ||
    (book.ownerEmail ?? "").toLowerCase() === (user.email ?? "").toLowerCase()
  );
}

/** Removes contact and account identifiers before a book leaves a public API. */
function toPublicBook(book) {
  if (!book) return book;
  const publicBook = { ...book };
  delete publicBook.ownerName;
  delete publicBook.ownerEmail;
  delete publicBook.ownerUserId;
  return publicBook;
}

/**
 * Reads the "copies" value from an add-book request and turns it into a
 * safe positive whole number (defaults to 1 copy when missing/invalid).
 */
function parseTotalCopies(value) {
  const copies = Number.parseInt(value, 10);
  if (Number.isInteger(copies) && copies > 0) return copies;
  return 1;
}

app.post("/add-books", async (req, res) => {
  const user = await getAuthedUser(req);
  if (!user) {
    return res.status(401).send({ error: "Please log in to add a book." });
  }

  const data = req.body;
  // Stamp a createdAt date (used for "New Arrivals" newest-first sorting).
  // The two copy counters always travel together: totalCopies is what the
  // owner entered and availableCopies starts out equal to it.
  const totalCopies = parseTotalCopies(data.totalCopies);
  // When the caller is signed in, remember WHO owns this book — the owner
  // (and, for older books, the ownerEmail) is what /my-books and the
  // update / delete permission check rely on.
  const result = await booksCollection.insertOne({
    ...data,
    ownerUserId: user ? user._id : null,
    // A signed-in caller's ownerEmail always comes from the verified
    // identity — the request body can never claim someone else's email
    // (My Books matches by ownerEmail as a legacy fallback). Guests keep
    // the address they typed in the form.
    ownerEmail: (user.email ?? "").toLowerCase(),
    totalCopies,
    availableCopies: totalCopies,
    createdAt: new Date(data.createdAt ?? Date.now()),
  });
  res.send(result);
});
app.get("/all-books",async(req,res)=>{
  const result = await booksCollection.find({}).sort({ createdAt: -1 }).toArray();
  res.send(result.map(toPublicBook));
})

// Get one book by its MongoDB ID (e.g. /book/6aeb69efaaab895ddf6d8480)
app.get("/book/:id", async (req, res) => {
  try {
    const result = await booksCollection.findOne({
      _id: new ObjectId(req.params.id),
    });
    res.send(toPublicBook(result));
  } catch (error) {
    // Unknown/invalid ID or database issue -> nothing found
    res.send(null);
  }
})
/* -------------------------------------------------------------------------- */
/*  Borrow system                                                             */
/* -------------------------------------------------------------------------- */

/**
 * /borrow-book — borrow one physical copy of a book.
 *
 * Copy safety rules (all enforced here, not in the browser):
 *  1. The caller must be signed in — the user comes from the verified
 *     Bearer JWT / session cookie (see getAuthedUser), never from the
 *     request body.
 *  2. The book must exist.
 *  3. The same user cannot borrow the same book twice at once.
 *     Older books added before this feature may miss the counter, so it
 *     is initialised from totalCopies first, exactly once.
 *  4. The copies counter is decremented atomically ONLY when it is above
 *     zero — two simultaneous borrows can never both take the last copy.
 *  5. The borrow record is inserted after a copy was successfully taken;
 *     if that insert ever failed the copy would be given back immediately.
 */
app.post("/borrow-book", async (req, res) => {
  try {
    const user = await getAuthedUser(req);
    if (!user) {
      return res
        .status(401)
        .send({ error: "Please log in to borrow books." });
    }

    const { bookId } = req.body;

    if (!bookId) {
      return res
        .status(400)
        .send({ error: "A book ID is required." });
    }

    // The borrow record keeps the SAME userId shape the older records
    // already use (the hex string), so /my-borrows and the unique index
    // keep matching everything.
    const userId = String(user._id);

    let book;
    try {
      book = await booksCollection.findOne({
        _id: new ObjectId(String(bookId)),
      });
    } catch {
      book = null;
    }
    if (!book) return res.status(404).send({ error: "Book not found." });

    // Rule 3 — one active borrow per user per book.
    const alreadyBorrowed = await borrowsCollection.findOne({
      bookId: book._id.toString(),
      userId,
      status: "borrowed",
    });
    if (alreadyBorrowed) {
      return res
        .status(409)
        .send({ error: "You have already borrowed this book." });
    }

    // Older books may not have a copies counter yet — initialise it once.
    if (typeof book.availableCopies !== "number") {
      await booksCollection.updateOne(
        { _id: book._id },
        { $set: { availableCopies: book.totalCopies || 1 } }
      );
    }

    // Rule 4 — atomically take one copy or fail. modifiedCount is 0 when
    // the match (availableCopies > 0) did not hold for ANY document.
    const updatedBook = await booksCollection.findOneAndUpdate(
      { _id: book._id, availableCopies: { $gt: 0 } },
      { $inc: { availableCopies: -1 } },
      { returnDocument: "after" }
    );

    if (!updatedBook) {
      return res
        .status(409)
        .send({ error: "Currently unavailable — no copies left." });
    }

    // Save the borrow record.       (bookId stored as string for consistency)
    // The unique index from above may reject a *concurrent* duplicate active
    // borrow here (code 11000) — either way the taken copy goes back first.
    let borrowResult;
    try {
      borrowResult = await borrowsCollection.insertOne({
        bookId: book._id.toString(),
        userId,
        userName: user.name ?? "Anonymous reader",
        userEmail: user.email ?? "",
        status: "borrowed",
        borrowedAt: new Date(),
        returnedAt: null,
      });
    } catch (insertError) {
      await booksCollection.updateOne(
        { _id: book._id },
        { $inc: { availableCopies: 1 } }
      );
      if (insertError && insertError.code === 11000) {
        return res
          .status(409)
          .send({ error: "You have already borrowed this book." });
      }
      throw insertError;
    }

    // Rule 5 — if the record could not be saved, undo the decrement so the
    // copy count stays accurate.
    if (!borrowResult.insertedId) {
      await booksCollection.updateOne(
        { _id: book._id },
        { $inc: { availableCopies: 1 } }
      );
      return res
        .status(500)
        .send({ error: "Could not save the borrow. Please try again." });
    }

    res.send({
      success: true,
      borrowId: borrowResult.insertedId.toString(),
      availableCopies: updatedBook.availableCopies,
    });
  } catch (error) {
    console.error("Borrow error:", error);
    res
      .status(500)
      .send({ error: "Something went wrong. Please try again." });
  }
});

/**
 * /return-book — return a borrowed copy.
 *
 * The caller must be signed in and must OWN the record — identity comes
 * from the verified session/JWT (see getAuthedUser), and the ownership
 * check runs BEFORE anything is modified, so a caller can never return
 * someone else's borrow. The status is still flipped from "borrowed" to
 * "returned" atomically, so a record that is already returned can never
 * match again — this prevents returning the same record twice and
 * double-counting copies.
 */
app.post("/return-book", async (req, res) => {
  try {
    const user = await getAuthedUser(req);
    if (!user) {
      return res.status(401).send({ error: "Please log in first." });
    }

    const borrowId = req.body?.borrowId;
    if (!borrowId) {
      return res.status(400).send({ error: "Borrow ID is required." });
    }

    // Locate the record by EITHER _id shape (old records store a plain
    // string instead of an ObjectId) WITHOUT modifying it, so the
    // ownership check can run first.
    let borrowDoc;
    try {
      borrowDoc = await borrowsCollection.findOne({
        _id: { $in: [new ObjectId(String(borrowId)), String(borrowId)] },
      });
    } catch {
      borrowDoc = null;
    }

    // Same message as before whether the record is gone, already
    // returned or the id was invalid.
    if (!borrowDoc || borrowDoc.status !== "borrowed") {
      return res
        .status(409)
        .send({ error: "This book was already returned." });
    }

    // Ownership check — the record's stored userEmail also allows older
    // records (created before signed-in borrowing existed) to be
    // returned by their borrower.
    const ownsRecord =
      String(borrowDoc.userId) === String(user._id) ||
      (borrowDoc.userEmail ?? "").toLowerCase() ===
        (user.email ?? "").toLowerCase();
    if (!ownsRecord) {
      return res
        .status(403)
        .send({ error: "You can only return your own borrows." });
    }

    // Marking a borrow returned and restoring its copy must commit together.
    // MongoDB transactions prevent a DB failure between these writes from
    // leaving the record returned while the copy count is still decremented.
    const session = client.startSession();
    let returnResult;
    try {
      await session.withTransaction(async () => {
        const updatedBorrow = await borrowsCollection.findOneAndUpdate(
          {
            _id: { $in: [new ObjectId(String(borrowId)), String(borrowId)] },
            status: "borrowed",
          },
          { $set: { status: "returned", returnedAt: new Date() } },
          { returnDocument: "after", session }
        );

        if (!updatedBorrow) {
          returnResult = { conflict: true };
          return;
        }

        const updatedBook = await booksCollection.findOneAndUpdate(
          { _id: new ObjectId(updatedBorrow.bookId) },
          { $inc: { availableCopies: 1 } },
          { returnDocument: "after", session }
        );

        returnResult = {
          success: true,
          status: "returned",
          availableCopies: updatedBook ? updatedBook.availableCopies : null,
        };
      });
    } finally {
      await session.endSession();
    }

    if (!returnResult || returnResult.conflict) {
      return res.status(409).send({ error: "This book was already returned." });
    }
    res.send(returnResult);
  } catch (error) {
    console.error("Return error:", error);
    res
      .status(500)
      .send({ error: "Something went wrong. Please try again." });
  }
});

/**
 * /my-borrows/:userId — the borrowing history of the SIGNED-IN user (newest
 * first), enriched with the borrowed book's title / author / cover so the
 * "My Borrows" table can be rendered in one request. Returned records stay
 * saved here with status "returned" for bookkeeping but are never listed.
 *
 * The :userId parameter must equal the verified session/JWT identity — the
 * backend accepts identity only from the signature, never from the URL.
 */
app.get("/my-borrows/:userId", async (req, res) => {
  try {
    const user = await getAuthedUser(req);
    if (!user) {
      return res
        .status(401)
        .send({ error: "Please log in to see your borrows." });
    }
    if (String(req.params.userId) !== String(user._id)) {
      return res
        .status(403)
        .send({ error: "You can only view your own borrows." });
    }

    const borrows = await borrowsCollection
      .find({ userId: req.params.userId, status: "borrowed" })
      .sort({ borrowedAt: -1 })
      .toArray();

    // Collect every referenced book, then look them all up in one query.
    const bookIdStrings = [...new Set(borrows.map((b) => b.bookId))];
    const bookDocs =
      bookIdStrings.length > 0
        ? await booksCollection
            .find({
              _id: { $in: bookIdStrings.map((id) => new ObjectId(id)) },
            })
            .toArray()
        : [];

    // Map the books by their string id for quick joins below.
    const booksById = new Map(
      bookDocs.map((book) => [book._id.toString(), book])
    );

    const result = borrows.map((borrow) => ({
      ...borrow,
      book: toPublicBook(booksById.get(borrow.bookId) ?? null),
    }));

    res.send(result);
  } catch (error) {
    console.error("My borrows error:", error);
    res.send([]);
  }
});

/* -------------------------------------------------------------------------- */
/*  My Books (owner-protected update & delete)                                */
/* -------------------------------------------------------------------------- */

/**
 * /my-books — books owned by the signed-in user, newest first.
 *
 * The signed-in user is resolved from the better-auth session cookie (see
 * getAuthedUser) — never from a client-sent userId — so a caller can only
 * ever list their own books. ownership matches ownerUserId first (stamped
 * when the book was added through a signed-in session) and falls back to
 * the ownerEmail for books added earlier.
 */
app.get("/my-books", async (req, res) => {
  try {
    const user = await getAuthedUser(req);
    if (!user) {
      return res
        .status(401)
        .send({ error: "Please log in to see your books." });
    }

    const result = await booksCollection
      .find({
        $or: [
          { ownerUserId: { $in: [user._id, String(user._id)] } },
          { ownerEmail: (user.email ?? "").toLowerCase() },
        ],
      })
      .sort({ createdAt: -1 })
      .toArray();
    res.send(result);
  } catch (error) {
    console.error("My books error:", error);
    res
      .status(500)
      .send({ error: "Could not load your books. Please try again." });
  }
});

/**
 * /update-book/:id — change an owned book's information.
 *
 * The caller's session is verified and the ownership check runs BEFORE any
 * request-body field is accepted, so a signed-in user can never update a
 * book that is not theirs. Borrowed copies are protected while the total
 * changes: currently-out copies = old total − old available, so the new
 * available count simply shifts by the same difference (never below 0).
 */
app.put("/update-book/:id", async (req, res) => {
  try {
    const user = await getAuthedUser(req);
    if (!user) {
      return res.status(401).send({ error: "Please log in first." });
    }

    let book;
    try {
      book = await booksCollection.findOne({
        _id: new ObjectId(req.params.id),
      });
    } catch {
      book = null;
    }
    if (!book) return res.status(404).send({ error: "Book not found." });
    if (!ownsBook(book, user)) {
      return res.status(403).send({ error: "You can only update your own books." });
    }

    // The edit form always sends every field (like the add form), so the
    // same required-field and URL checks apply here.
    const data = req.body ?? {};
    const missing = ["title", "author", "category", "imageUrl", "description"].filter(
      (field) => !String(data[field] ?? "").trim()
    );
    if (missing.length > 0) {
      return res
        .status(400)
        .send({ error: `Please fill out: ${missing.join(", ")}.` });
    }

    let safeUrl;
    try {
      safeUrl = new URL(String(data.imageUrl));
    } catch {
      safeUrl = null;
    }
    if (!safeUrl || !["http:", "https:"].includes(safeUrl.protocol)) {
      return res
        .status(400)
        .send({
          error: "Please provide a valid image URL starting with http(s)://",
        });
    }

    const totalCopies = parseTotalCopies(data.totalCopies);
    const borrowedNow = Math.max(
      0,
      (book.totalCopies || 1) - (typeof book.availableCopies === "number" ? book.availableCopies : book.totalCopies || 1)
    );
    const availableCopies = Math.max(0, totalCopies - borrowedNow);

    const updatedBook = await booksCollection.findOneAndUpdate(
      { _id: book._id },
      {
        $set: {
          title: String(data.title).trim(),
          author: String(data.author).trim(),
          category: String(data.category).trim(),
          tags: String(data.tags ?? "").trim(),
          imageUrl: String(data.imageUrl).trim(),
          description: String(data.description).trim(),
          totalCopies,
          availableCopies,
        },
      },
      { returnDocument: "after" }
    );

    res.send({ success: true, book: updatedBook });
  } catch (error) {
    console.error("Update book error:", error);
    res
      .status(500)
      .send({ error: "Could not update the book. Please try again." });
  }
});

/**
 * /delete-book/:id — permanently remove an owned book.
 *
 * Same session + ownership verification as the update route. Borrow
 * records that reference the book are kept (the "My Borrows" page already
 * renders a friendly "Book removed" row for them).
 */
app.delete("/delete-book/:id", async (req, res) => {
  try {
    const user = await getAuthedUser(req);
    if (!user) {
      return res.status(401).send({ error: "Please log in first." });
    }

    let book;
    try {
      book = await booksCollection.findOne({
        _id: new ObjectId(req.params.id),
      });
    } catch {
      book = null;
    }
    if (!book) return res.status(404).send({ error: "Book not found." });
    if (!ownsBook(book, user)) {
      return res.status(403).send({ error: "You can only delete your own books." });
    }

    const result = await booksCollection.deleteOne({ _id: book._id });
    if (result.deletedCount !== 1) {
      return res
        .status(500)
        .send({ error: "Could not delete the book. Please try again." });
    }

    res.send({ success: true });
  } catch (error) {
    console.error("Delete book error:", error);
    res
      .status(500)
      .send({ error: "Could not delete the book. Please try again." });
  }
});

app.get("/", (req, res) => {
  res.send("Hello, World!");
});
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
