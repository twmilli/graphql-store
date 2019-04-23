const { forwardTo } = require("prisma-binding");
const { hasPermission } = require("../utils");

const Query = {
  items: forwardTo("db"),
  item: forwardTo("db"),
  itemsConnection: forwardTo("db"),
  me(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      return null;
    }
    return ctx.db.query.user(
      {
        where: { id: ctx.request.userId }
      },
      info
    );
  },
  async users(parent, args, ctx, info) {
    // check if the user has permissions to query all users
    if (!ctx.request.userId) {
      throw new Error("You must be logged in!");
    }
    const user = await ctx.db.query.user({
      where: { id: ctx.request.userId }
    });
    hasPermission(ctx.request.user, ["ADMIN", "PERMISSIONUPDATE"]);
    return ctx.db.query.users({}, info);
  }
};

module.exports = Query;
