const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { randomBytes } = require("crypto");
const { promisify } = require("util");
const { transport, makeEmail } = require("../mail");
const { hasPermission } = require("../utils");

const Mutations = {
  async createItem(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      throw new Error("You must be logged in to do that!");
    }
    const item = await ctx.db.mutation.createItem(
      {
        data: {
          user: {
            connect: {
              id: ctx.request.userId
            }
          },
          ...args
        }
      },
      info
    );
    return item;
  },

  updateItem(parent, args, ctx, info) {
    const updates = { ...args };
    delete updates.id;
    return ctx.db.mutation.updateItem(
      {
        data: updates,
        where: {
          id: args.id
        }
      },
      info
    );
  },

  async deleteItem(parent, args, ctx, info) {
    const where = { id: args.id };
    const item = await ctx.db.query.item(
      { where },
      `
    {id title user { id }}`
    );

    const ownsItem = item.user.id === ctx.request.userId;
    const hasPermissions = ctx.request.user.permissions.some(permission =>
      ["ADMIN", "ITEMDELETE"].includes(permission)
    );

    if (ownsItem || hasPermissions) {
      return ctx.db.mutation.deleteItem({ where }, info);
    }
    throw new Error("You don't have permission to delete this item");
  },

  async signup(parent, args, ctx, info) {
    args.email = args.email.toLowerCase();
    const password = await bcrypt.hash(args.password, 10);
    const user = await ctx.db.mutation.createUser(
      {
        data: {
          ...args,
          password,
          permissions: { set: ["USER"] }
        }
      },
      info
    );
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });
    return user;
  },

  async signin(parent, { email, password }, ctx, info) {
    const user = await ctx.db.query.user({
      where: { email }
    });
    if (!user) {
      throw new Error(`No such user found for email ${email}`);
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new Error("Invalid Password!");
    }
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });

    return user;
  },

  signout(parent, args, ctx, info) {
    ctx.response.clearCookie("token");
    return { message: "Goodbye!" };
  },

  async requestReset(parent, args, ctx, info) {
    const user = await ctx.db.query.user({
      where: { email: args.email }
    });

    if (!user) {
      throw new Error(`No user with email ${args.email}`);
    }
    const randomBytesPromisified = promisify(randomBytes);
    const resetToken = (await randomBytesPromisified(20)).toString("hex");
    const resetTokenExpiry = Date.now() + 3600000; // 1 hr from now
    const res = ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry }
    });

    const mailRes = await transport.sendMail({
      from: "twm013@bucknell.edu",
      to: user.email,
      subject: "Your Password Reset Token",
      html: makeEmail(`Your Password Reset Token is here! \n\n
      <a href=${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}>
      Click Here to Reset</a>`)
    });

    return { message: "Thanks!" };
  },

  async resetPassword(
    parent,
    { password, confirmPassword, resetToken },
    ctx,
    info
  ) {
    if (password != confirmPassword) {
      throw new Error("Passwords do not match!");
    }
    const [user] = await ctx.db.query.users({
      where: { resetToken, resetTokenExpiry_gte: Date.now() - 3600000 }
    });
    if (!user) {
      throw new Error("This token is either invalid or expired!");
    }

    const newPassword = await bcrypt.hash(password, 10);
    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: {
        password: newPassword,
        resetToken: null,
        resetTokenExpiry: null
      }
    });
    const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });
    return updatedUser;
  },

  async updatePermissions(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      throw new Error("Must be logged in to modify permissions");
    }
    hasPermission(ctx.request.user, ["ADMIN", "PERMISSIONUPDATE"]);

    return ctx.db.mutation.updateUser(
      {
        data: {
          permissions: {
            set: args.permissions
          }
        },
        where: { id: args.userId }
      },
      info
    );
  },

  async addToCart(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      throw new Error("Must be signed in");
    }

    const { userId } = ctx.request;
    const [existingCartItem] = await ctx.db.query.cartItems({
      where: {
        user: { id: userId },
        item: { id: args.id }
      }
    });
    if (existingCartItem) {
      console.log("Item already in cart");
      return ctx.db.mutation.updateCartItem(
        {
          where: { id: existingCartItem.id },
          data: {
            quantity: existingCartItem.quantity + 1
          }
        },
        info
      );
    }
    return ctx.db.mutation.createCartItem(
      {
        data: {
          quantity: 1,
          item: { connect: { id: args.id } },
          user: { connect: { id: userId } }
        }
      },
      info
    );
  }
};

module.exports = Mutations;
