/* Shared relations contract bridge for the classic Portail script. */
import * as contract from './relations-contract.js'
import * as feedback from './feedback-contract.js'

window.SPIDRelations = Object.freeze({ contract, feedback })
