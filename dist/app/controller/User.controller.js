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
exports.GetsUserDisp = exports.UpdateUserById = exports.DeleteUserById = exports.GetUserById = exports.CreateUserBySucursal = exports.GetUsersByEmpresaAndSucursal = void 0;
const sequelize_1 = require("sequelize");
const Empresa_1 = __importDefault(require("../models/Empresa"));
const Sucursales_1 = __importDefault(require("../models/Sucursales"));
const Users_1 = __importDefault(require("../models/Users"));
const Dispositvo_1 = __importDefault(require("../models/Dispositvo"));
const GetUsersByEmpresaAndSucursal = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { empresa, sucursal } = req.params;
        const UserData = yield Users_1.default.findAll({
            include: [
                {
                    model: Sucursales_1.default,
                    where: {
                        nombre: { [sequelize_1.Op.eq]: sucursal },
                    },
                    include: [
                        {
                            model: Empresa_1.default,
                            where: {
                                nombre: { [sequelize_1.Op.eq]: empresa },
                            },
                        },
                    ],
                },
                {
                    model: Dispositvo_1.default,
                },
            ],
        });
        return res.json(UserData);
    }
    catch (error) {
        res.json(error);
    }
});
exports.GetUsersByEmpresaAndSucursal = GetUsersByEmpresaAndSucursal;
const CreateUserBySucursal = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { empresa, sucursal } = req.params;
        const datoUser = req.body;
        const resSuc = yield Sucursales_1.default.findOne({
            where: {
                nombre: {
                    [sequelize_1.Op.eq]: sucursal,
                },
            },
            include: [
                {
                    model: Empresa_1.default,
                    where: {
                        nombre: { [sequelize_1.Op.eq]: empresa },
                    },
                },
            ],
        });
        if (resSuc) {
            const CreateUser = yield Users_1.default.create(Object.assign(Object.assign({}, datoUser), { IdSucursal: resSuc === null || resSuc === void 0 ? void 0 : resSuc.id }));
            res.json({ create: true });
        }
        return res.json({ create: false });
    }
    catch (error) { }
});
exports.CreateUserBySucursal = CreateUserBySucursal;
const GetUserById = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    try {
        const resp = yield Users_1.default.findOne({
            where: {
                id,
            },
            include: [
                {
                    model: Dispositvo_1.default,
                },
            ],
        });
        if (!resp)
            return res.json({ where: false });
        res.json({ where: true, resp });
    }
    catch (error) {
        res.json(500).json(error);
    }
});
exports.GetUserById = GetUserById;
const DeleteUserById = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { id } = req.params;
        const Exist = yield Users_1.default.findOne({
            where: { id },
        });
        console.log(id);
        if (Exist) {
            yield Users_1.default.destroy({
                where: {
                    id,
                },
            });
            return res.json({ search: true });
        }
        res.json({ search: false });
    }
    catch (error) {
        console.log(error);
    }
});
exports.DeleteUserById = DeleteUserById;
const UpdateUserById = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { id } = req.params;
        const NewDatos = req.body;
        const Exist = yield Users_1.default.findByPk(id);
        const cambios = {};
        if (!Exist)
            return res.json({ search: false });
        for (const CamposUpdate in NewDatos) {
            if (Exist[CamposUpdate] !== NewDatos[CamposUpdate]) {
                cambios[CamposUpdate] = NewDatos[CamposUpdate];
            }
        }
        yield Exist.update(cambios);
        res.json({ search: true, data: Exist, cambios });
    }
    catch (error) { }
});
exports.UpdateUserById = UpdateUserById;
const GetsUserDisp = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { empresa, sucursal } = req.query;
        console.log("llego");
        const resp = yield Users_1.default.findAll({
            include: [
                {
                    model: Sucursales_1.default,
                    where: {
                        nombre: sucursal,
                    },
                    include: [
                        {
                            model: Empresa_1.default,
                            where: {
                                nombre: empresa,
                            },
                        },
                    ],
                },
                {
                    model: Dispositvo_1.default
                }
            ],
        });
        res.json(resp);
    }
    catch (error) {
        console.log(error);
    }
});
exports.GetsUserDisp = GetsUserDisp;
