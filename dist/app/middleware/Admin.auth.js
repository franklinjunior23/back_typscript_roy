"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ValidateAdminToken = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
require("dotenv/config");
function ValidateAdminToken(req, res, next) {
    return __awaiter(this, void 0, void 0, function* () {
        const tokenUser = req.header(String(process.env.VALIDATION_HEADER));
        if (!tokenUser)
            return res.status(401).json({ message: "Token not provided" });
        try {
            const Decoded = yield jsonwebtoken_1.default.verify(tokenUser, process.env.SECRET_KEY_JWT || "");
            if (Decoded.datos.Role.nombre === "Administrador")
                return next();
            throw new Error("Invalid credentials required");
        }
        catch (error) {
            console.log(error);
            return res.status(401).json({ message: "Acceso denegado. No tienes el rol requerido para esta acción." });
        }
    });
}
exports.ValidateAdminToken = ValidateAdminToken;
