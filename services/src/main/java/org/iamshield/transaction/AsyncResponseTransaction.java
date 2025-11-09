package org.iamshield.transaction;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldTransaction;
import org.iamshield.models.IAMShieldTransactionManager;
import org.iamshield.services.ErrorPage;
import org.iamshield.services.messages.Messages;

import jakarta.ws.rs.container.AsyncResponse;
import jakarta.ws.rs.core.Response;

/**
 * When using {@link AsyncResponse#resume(Object)} directly in the code, the response is returned before all changes 
 * done withing this execution are committed. Therefore we need some mechanism that resumes the AsyncResponse after all
 * changes are successfully committed. This can be achieved by enlisting an instance of AsyncResponseTransaction into
 * the main transaction using {@link org.iamshield.models.IAMShieldTransactionManager#enlistAfterCompletion(IAMShieldTransaction)}.
 */
public class AsyncResponseTransaction implements IAMShieldTransaction {

    private final IAMShieldSession session;
    private final AsyncResponse responseToFinishInTransaction;
    private final Response responseToSend;

    /**
     * This method creates a new AsyncResponseTransaction instance that resumes provided AsyncResponse
     * {@code responseToFinishInTransaction} with given Response {@code responseToSend}. The transaction is enlisted 
     * to {@link IAMShieldTransactionManager}.
     *
     * @param session Current IAMShieldSession
     * @param responseToFinishInTransaction AsyncResponse to be resumed on {@link IAMShieldTransactionManager} commit/rollback.
     * @param responseToSend Response to be sent
     */
    public static void finishAsyncResponseInTransaction(IAMShieldSession session, AsyncResponse responseToFinishInTransaction, Response responseToSend) {
        session.getTransactionManager().enlistAfterCompletion(new AsyncResponseTransaction(session, responseToFinishInTransaction, responseToSend));
    }
    
    private AsyncResponseTransaction(IAMShieldSession session, AsyncResponse responseToFinishInTransaction, Response responseToSend) {
        this.session = session;
        this.responseToFinishInTransaction = responseToFinishInTransaction;
        this.responseToSend = responseToSend;
    }

    @Override
    public void begin() {

    }

    @Override
    public void commit() {
        responseToFinishInTransaction.resume(responseToSend);
    }

    @Override
    public void rollback() {
        responseToFinishInTransaction.resume(ErrorPage.error(session, null, Response.Status.INTERNAL_SERVER_ERROR, Messages.INTERNAL_SERVER_ERROR));
    }

    @Override
    public void setRollbackOnly() {

    }

    @Override
    public boolean getRollbackOnly() {
        return false;
    }

    @Override
    public boolean isActive() {
        return false;
    }
}
